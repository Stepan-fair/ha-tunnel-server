"""Transactional one-use enrollment; high-entropy secrets stored as SHA-256 hashes."""
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone as utc_timezone
import hashlib
import hmac
import secrets
import sqlite3
import json
import time
from pathlib import Path

from shared import validation
from shared.protocol import Client, Credentials, Enrollment
from server.app.migrations import migrate
from server.app.duration import deadline_at, parse_duration
from server.app.journal import Actor, append_event


class ConflictError(ValueError):
    def __init__(self, message, *, client_id=None):
        super().__init__(message)
        self.client_id = client_id


def digest(value: str) -> str:
    return hashlib.sha256(value.encode('ascii')).hexdigest()


class Store:
    def __init__(self, path: Path, base_domain: str, reserved=(), server_host=None, *, clock=None, vault=None):
        self.clock = clock
        self.migrating=False
        self.vault = vault
        self.live_proxies = {}
        self.live_sessions = {}
        self.login_sessions = {}
        self.path = Path(path)
        self.base_domain = validation.domain(base_domain)
        self.reserved = set(reserved) | {'tunnel', 'www', 'mail', 'smtp', 'ftp', 'admin', 'api'}
        if server_host is not None:
            host=validation.domain(server_host)
            if host.split('.')[1:]!=self.base_domain.split('.'):
                raise ValueError('Server host must be a subdomain of base_domain')
            self.reserved.add(host.split('.')[0])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS clients (
              id TEXT PRIMARY KEY, domain TEXT UNIQUE NOT NULL, code_hash TEXT UNIQUE,
              issued INTEGER NOT NULL, expires INTEGER NOT NULL, secret_hash TEXT,
              revoked INTEGER NOT NULL DEFAULT 0, last_seen INTEGER)''')
            migrate(db)
            for row in db.execute('SELECT domain FROM clients WHERE revoked=0'):
                if row['domain'].split('.')[0] in self.reserved:
                    raise ValueError('Existing client conflicts with a reserved server name')
        self.path.chmod(0o600)

    def now(self):
        return self.clock.now() if hasattr(self.clock, 'now') else (self.clock or time.time)()

    def _vault(self, db):
        from server.app.invitations import InvitationVault
        return self.vault or InvitationVault(self.path.parent, require_existing=bool(
            db.execute('SELECT 1 FROM clients WHERE code_ciphertext IS NOT NULL LIMIT 1').fetchone()))

    def show_code(self, client_id, now, *, actor=None):
        with self.connection() as db:
            row = db.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
            if row is None or not row['code_hash'] or not row['issued'] <= now < row['expires'] or not row['code_ciphertext']:
                raise ValueError('Issue a new connection code for this client')
            code = self._vault(db).open(client_id, row['code_ciphertext'])
            if not hmac.compare_digest(digest(code), row['code_hash']):
                raise ValueError('Invalid invitation state')
            append_event(db, action='show_code', actor=actor, client_id=client_id, domain=row['domain'], at=now)
            return Enrollment(client_id, row['domain'], code, row['expires'])

    def reissue(self, client_id, now, *, actor=None):
        if self.migrating: raise ConflictError('Domain migration is in progress')
        code = secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
            if row is None:
                raise ValueError('Unknown client')
            cipher = self._vault(db).seal(client_id, code)
            db.execute('UPDATE clients SET code_hash=?,code_ciphertext=?,issued=?,expires=? WHERE id=?',
                       (digest(code), cipher, now, now+900, client_id))
            append_event(db, action='reissue', actor=actor, client_id=client_id, domain=row['domain'], at=now)
        return Enrollment(client_id, row['domain'], code, now+900)

    def _snapshot(self, row, now):
        from server.app.subscription import billing_snapshot
        reliable=not hasattr(self.clock,'reliable') or self.clock.reliable
        billing=billing_snapshot(row,now,reliable=reliable)
        monthly=row['billing_mode']!='legacy'
        deadline=(row['paid_until'] if row['price_kopecks']>0 else None) if monthly else row['deadline']
        expired=(row['price_kopecks']>0 and (deadline is None or row['paid_from'] is None or now<row['paid_from'] or now>=deadline)) if monthly else deadline is not None and now>=deadline
        clock_error = (row['price_kopecks']>0 if monthly else deadline is not None) and not reliable
        state = ('revoked' if row['revoked'] else 'pending' if not row['secret_hash'] else
                 'paused' if monthly and row['paused'] else 'clock_error' if monthly and clock_error else
                 'expired' if expired else 'paused' if row['paused'] else 'clock_error' if clock_error else 'allowed')
        if self.migrating and state=='allowed': state='clock_error'
        return dict(client_id=row['id'], id=row['id'], domain=row['domain'], enrolled=bool(row['secret_hash']),
            revoked=bool(row['revoked']), paused=bool(row['paused']), expired=expired, access_state=state,
            deadline=deadline, duration=json.loads(row['duration']) if row['duration'] else None, billing=billing,
            timezone=row['timezone'], revision=row['revision'], generation=row['generation'],
            capabilities=json.loads(row['capabilities']), editable=bool(row['secret_hash']) and not bool(row['revoked']),
            to_client_bytes=row['to_client_bytes'], from_client_bytes=row['from_client_bytes'],
            traffic_started_at=row['traffic_started_at'], last_seen=row['last_seen'],
            issued=row['issued'], expires=row['expires'])

    def access_snapshot(self, client_id, now):
        with self.connection() as db:
            row = db.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
        if row is None:
            raise ValueError('Unknown client')
        return self._snapshot(row, now)

    def client_by_domain(self, domain):
        with self.connection() as db:
            row = db.execute('SELECT id,domain FROM clients WHERE domain=?', (domain,)).fetchone()
        return Client(row['id'], row['domain']) if row else None

    def get_metadata(self, name, default=None):
        with self.connection() as db:
            row = db.execute('SELECT value FROM server_metadata WHERE name=?', (name,)).fetchone()
        return json.loads(row['value']) if row else default

    def set_metadata(self, name, value):
        with self.connection() as db:
            if name == 'clock_anchor':
                old = db.execute('SELECT value FROM server_metadata WHERE name=?', (name,)).fetchone()
                value = max(float(value), json.loads(old['value']) if old else 0)
            db.execute('INSERT OR REPLACE INTO server_metadata VALUES (?,?)', (name, json.dumps(value)))

    def set_capabilities(self, client_id, capabilities):
        if (not isinstance(capabilities, list) or len(capabilities) > 2 or
                any(c not in ('access-v1', 'telemetry-v1') for c in capabilities)):
            raise ValueError('Invalid capabilities')
        with self.connection() as db:
            if db.execute('UPDATE clients SET capabilities=? WHERE id=?',
                          (json.dumps(sorted(set(capabilities))), client_id)).rowcount != 1:
                raise ValueError('Unknown client')

    def apply_access(self, client_id, action, command_id, expected_revision, now,
                     duration=None, timezone='UTC', *, actor=None):
        if (action not in ('pause', 'start', 'set_duration', 'permanent', 'revoke') or
                not isinstance(command_id, str) or not 1 <= len(command_id) <= 128 or
                type(expected_revision) is not int or expected_revision < 0):
            raise ValueError('Invalid access command')
        if self.migrating: raise ConflictError('Domain migration is in progress')
        request = json.dumps([action, expected_revision, duration, timezone], sort_keys=True)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT * FROM access_commands WHERE client_id=? AND command_id=?', (client_id, command_id)).fetchone()
            if previous:
                if previous['request'] != request:
                    raise ValueError('Command identifier was reused')
                return json.loads(previous['result'])
            row = db.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
            if row is None:
                raise ValueError('Unknown client')
            snap = self._snapshot(row, now)
            if row['billing_mode']=='monthly' and action in ('set_duration','permanent'):
                raise ConflictError('Use subscription price and balance')
            if row['revision'] != expected_revision:
                raise ConflictError('Client policy has changed; refresh it')
            if action != 'revoke' and (row['revoked'] or not row['secret_hash']):
                raise ConflictError('Connect the client before changing access')
            paused, deadline, period, zone = row['paused'], row['deadline'], row['duration'], row['timezone']
            if action == 'pause':
                paused = 1
            elif action == 'start':
                paused = 0
                if row['billing_mode']=='monthly' and snap['expired']:
                    db.execute('UPDATE clients SET billing_paused=1 WHERE id=?',(client_id,))
                if row['billing_mode']!='monthly' and snap['expired'] and period:
                    deadline = deadline_at(datetime.fromtimestamp(now, utc_timezone.utc), parse_duration(json.loads(period)), zone).timestamp()
            elif action == 'set_duration':
                db.execute("UPDATE clients SET billing_mode='legacy' WHERE id=?",(client_id,))
                parsed = parse_duration(duration)
                deadline = deadline_at(datetime.fromtimestamp(now, utc_timezone.utc), parsed, timezone).timestamp()
                period, zone, paused = json.dumps(asdict(parsed)), timezone, 0
            elif action == 'permanent':
                db.execute("UPDATE clients SET billing_mode='free' WHERE id=?",(client_id,))
                paused, deadline, period = 0, None, None
            if action == 'revoke':
                db.execute('UPDATE clients SET revoked=1, code_hash=NULL, code_ciphertext=NULL, secret_hash=NULL, revision=revision+1 WHERE id=?', (client_id,))
            else:
                db.execute('UPDATE clients SET paused=?,deadline=?,duration=?,timezone=?,revision=revision+1 WHERE id=?', (paused, deadline, period, zone, client_id))
            updated=db.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
            updated=self.reconcile_billing(db,updated,now,fresh_start=action=='start' and snap['expired'])
            result = self._snapshot(updated, now)
            db.execute('INSERT INTO access_commands VALUES (?,?,?,?)', (client_id, command_id, request, json.dumps(result)))
            append_event(db, action=action, actor=actor, client_id=client_id, domain=row['domain'], at=now,
                         details={'deadline':result['deadline'], 'revision':result['revision'], 'timezone':result['timezone']})
        return result

    def reconcile_billing(self,db,row,now,*,fresh_start=False):
        if row['billing_mode']!='monthly' or not getattr(self,'billing_available',lambda:True)():
            return row
        if hasattr(self.clock,'reliable') and not self.clock.reliable: return row
        from server.app.billing import BillingRepository
        return BillingRepository(self)._reconcile(db,row,now,row['billing_timezone'],fresh_start=fresh_start)

    def record_expiry(self, client_id, now):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
            if not row or row['revoked'] or row['deadline'] is None or now < row['deadline']: return False
            ident = f"expiry:{client_id}:{row['deadline']}"
            if db.execute('SELECT 1 FROM audit_events WHERE operation_id=?', (ident,)).fetchone(): return False
            append_event(db, action='expired', actor=Actor('timer'), client_id=client_id,
                         domain=row['domain'], at=now, operation_id=ident, details={'deadline':row['deadline']})
        return True

    def delete_revoked(self, client_id, expected_revision, *, actor=None):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM clients WHERE id=?',(client_id,)).fetchone()
            if row is None: raise ValueError('Unknown client')
            if not row['revoked'] or type(expected_revision) is not int or row['revision']!=expected_revision:
                raise ConflictError('Revoke the client and refresh before deleting it')
            append_event(db,action='delete',actor=actor,client_id=client_id,domain=row['domain'],at=self.now())
            db.execute('DELETE FROM access_commands WHERE client_id=?',(client_id,))
            db.execute('DELETE FROM billing_commands WHERE client_id=?',(client_id,))
            db.execute('DELETE FROM availability_checkpoint WHERE client_id=?',(client_id,))
            db.execute('DELETE FROM clients WHERE id=?',(client_id,))
            for name in ('ha_available','frp_connected'):
                db.execute('DELETE FROM server_metadata WHERE name=?',('audit:'+name+':'+client_id,))
        for cache in (self.live_proxies,self.live_sessions,self.login_sessions): cache.pop(client_id,None)
        return {'deleted':True,'client_id':client_id,'domain':row['domain']}

    def add_traffic(self, client_id, to_client, from_client):
        if any(type(v) is not int or not 0 <= v <= 2**63-1 for v in (to_client, from_client)):
            raise ValueError('Invalid byte counters')
        with self.connection() as db:
            if db.execute('UPDATE clients SET to_client_bytes=to_client_bytes+?, from_client_bytes=from_client_bytes+? WHERE id=? AND to_client_bytes<=? AND from_client_bytes<=?',
                (to_client, from_client, client_id, 2**63-1-to_client, 2**63-1-from_client)).rowcount != 1:
                raise ValueError('Unknown client or counter overflow')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def issue(self, name: str | None, now: int, *, actor=None) -> Enrollment:
        if self.migrating: raise ConflictError('Domain migration is in progress')
        name = validation.label(name if name is not None else 'ha-' + secrets.token_hex(5))
        if name in self.reserved:
            raise ValueError('Name is reserved')
        fqdn = validation.domain(f'{name}.{self.base_domain}')
        identifier, code = secrets.token_hex(16), secrets.token_urlsafe(32)
        try:
            with self.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                old=db.execute('SELECT id,revoked FROM clients WHERE domain=?',(fqdn,)).fetchone()
                if old and old['revoked']:
                    raise ConflictError('Restore this revoked client or delete it first',client_id=old['id'])
                generation=int(bool(db.execute("SELECT 1 FROM audit_events WHERE action='delete' AND domain=? LIMIT 1",(fqdn,)).fetchone()))
                cipher = self._vault(db).seal(identifier, code)
                db.execute('INSERT INTO clients(id,domain,code_hash,code_ciphertext,issued,expires,traffic_started_at,generation) VALUES (?,?,?,?,?,?,?,?)',
                           (identifier, fqdn, digest(code), cipher, now, now + 900, now,generation))
                append_event(db, action='issue', actor=actor, client_id=identifier, domain=fqdn, at=now)
        except sqlite3.IntegrityError as exc:
            raise ValueError('Name is already assigned') from exc
        return Enrollment(identifier, fqdn, code, now + 900)

    def redeem(self, code: str, now: int, expected_client_id=None, *, actor=None) -> Credentials:
        if self.migrating: raise ConflictError('Domain migration is in progress')
        validation.token(code)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM clients WHERE code_hash=?', (digest(code),)).fetchone()
            if row is None or not row['issued'] <= now < row['expires']:
                raise ValueError('Invalid or expired connection code')
            if expected_client_id is not None and row['id'] != expected_client_id:
                raise ValueError('Connection code belongs to a different client')
            secret = secrets.token_urlsafe(32)
            rebind = int(bool(row['revoked']) or row['status_secret_hash'] is not None)
            if row['revoked'] and row['billing_mode']!='monthly':
                deadline=deadline_at(datetime.fromtimestamp(now,utc_timezone.utc),parse_duration(json.loads(row['duration'])),row['timezone']).timestamp() if row['duration'] else None
                db.execute('UPDATE clients SET paused=0,deadline=? WHERE id=?',(deadline,row['id']))
            db.execute('UPDATE clients SET code_hash=NULL,code_ciphertext=NULL,secret_hash=?,status_secret_hash=?,revoked=0,generation=generation+?,revision=revision+?,traffic_started_at=COALESCE(traffic_started_at,?) WHERE id=?',
                       (digest(secret), digest(secret), rebind, rebind, now, row['id']))
            updated=db.execute('SELECT * FROM clients WHERE id=?',(row['id'],)).fetchone()
            self.reconcile_billing(db,updated,now)
            result = Credentials(row['id'], row['domain'], secret)
            append_event(db, action='redeem', actor=actor or Actor('client'), client_id=row['id'], domain=row['domain'], at=now)
        return result

    def authenticate(self, client_id: str, secret: str) -> Client | None:
        try:
            validation.token(secret)
        except ValueError:
            return None
        if not isinstance(client_id, str) or len(client_id) != 32:
            return None
        with self.connection() as db:
            row = db.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
        if row is None or row['revoked'] or not row['secret_hash']:
            return None
        if self._snapshot(row, self.now())['access_state'] != 'allowed':
            return None
        if not hmac.compare_digest(row['secret_hash'], digest(secret)):
            return None
        return Client(row['id'], row['domain'])

    def status_authenticate(self, client_id, secret):
        try:
            validation.token(secret)
        except ValueError:
            return None
        if not isinstance(client_id, str) or len(client_id) != 32:
            return None
        with self.connection() as db:
            row = db.execute('SELECT id,domain,status_secret_hash FROM clients WHERE id=?', (client_id,)).fetchone()
        return Client(row['id'], row['domain']) if row and row['status_secret_hash'] and hmac.compare_digest(row['status_secret_hash'], digest(secret)) else None

    def revoke(self, client_id: str, *, actor=None) -> None:
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT domain FROM clients WHERE id=?', (client_id,)).fetchone()
            cursor = db.execute('UPDATE clients SET revoked=1,code_hash=NULL,code_ciphertext=NULL,secret_hash=NULL,revision=revision+1 WHERE id=?',
                                (client_id,))
            if cursor.rowcount != 1:
                raise ValueError('Unknown client')
            append_event(db, action='revoke', actor=actor, client_id=client_id, domain=row['domain'], at=self.now())

    def seen(self, client_id: str, now: int) -> None:
        with self.connection() as db:
            db.execute('UPDATE clients SET last_seen=? WHERE id=? AND revoked=0', (now, client_id))

    def active(self, client_id: str) -> Client | None:
        if not isinstance(client_id, str):
            return None
        with self.connection() as db:
            row = db.execute('SELECT * FROM clients WHERE id=? AND revoked=0 AND secret_hash IS NOT NULL',
                             (client_id,)).fetchone()
        return Client(row['id'], row['domain']) if row and self._snapshot(row, self.now())['access_state']=='allowed' else None

    def list_clients(self) -> list[dict]:
        with self.connection() as db:
            return [self._snapshot(row, self.now()) for row in db.execute('SELECT * FROM clients ORDER BY issued,id')]
