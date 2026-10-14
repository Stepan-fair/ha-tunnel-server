"""Bounded, durable enrollment reservations; staged secrets have no authority."""
import hmac
import json
import re

from shared.validation import token
from server.app.store import digest, _has_binding, ConflictError, BoundDomainError
from server.app.journal import append_event, Actor

MAX_RECORDS = 4096
REPLAY_SECONDS = 86400


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS binding_operations (
        operation_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, domain TEXT NOT NULL,
        secret_hash TEXT NOT NULL, request_hash TEXT NOT NULL, code_hash TEXT NOT NULL,
        generation INTEGER NOT NULL, revision INTEGER NOT NULL, target_generation INTEGER NOT NULL,
        transfer INTEGER NOT NULL, expires REAL NOT NULL, retain_until REAL NOT NULL,
        state TEXT NOT NULL)''')
    db.execute('CREATE INDEX IF NOT EXISTS binding_client ON binding_operations(client_id,state)')


def _operation(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value):
        raise ValueError('Invalid operation identity')


def reserved(db, row, now):
    return db.execute('''SELECT 1 FROM binding_operations WHERE client_id=? AND code_hash=?
        AND generation=? AND revision=? AND state='prepared' AND expires>? LIMIT 1''',
        (row['id'],row['code_hash'],row['generation'],row['revision'],now)).fetchone() is not None


class BindingRepository:
    def __init__(self, store):
        self.store=store

    def _cleanup(self, db, now):
        db.execute('DELETE FROM binding_operations WHERE operation_id IN (SELECT operation_id FROM binding_operations WHERE retain_until<=? LIMIT 128)',(now,))

    def _row(self, db, operation_id, client_id, secret):
        _operation(operation_id)
        token(secret)
        op=db.execute('SELECT * FROM binding_operations WHERE operation_id=?',(operation_id,)).fetchone()
        if op is None or op['client_id']!=client_id or not hmac.compare_digest(op['secret_hash'],digest(secret)):
            raise ValueError('Unknown operation or invalid proof')
        return op

    def _state(self, db, op, now):
        row=db.execute('SELECT * FROM clients WHERE id=?',(op['client_id'],)).fetchone()
        state=op['state']
        if state=='prepared':
            if now>=op['expires']: state='expired'
            elif (self.store.migrating or row is None or
                  any(row[key]!=op[key] for key in ('domain','code_hash','generation','revision'))): state='superseded'
        current='superseded'
        if row is not None and row['domain']==op['domain'] and row['generation']==op['target_generation'] and row['status_secret_hash']==op['secret_hash']:
            current=self.store._snapshot(row,now)['access_state']
        return dict(operation_id=op['operation_id'],client_id=op['client_id'],domain=op['domain'],
            generation=op['target_generation'],state=state,current_state=current,
            expires=op['expires'],server_instance_id=self.store.get_metadata('instance_id'))

    def prepare(self, code, operation_id, secret, now, *, expected_client_id=None, binding_secret=None):
        _operation(operation_id)
        token(code); token(secret)
        if binding_secret is not None: token(binding_secret)
        if self.store.migrating: raise ConflictError('Domain migration is in progress')
        request_hash=digest(json.dumps([digest(code),expected_client_id,digest(binding_secret) if binding_secret else None],separators=(',',':')))
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self.store.ensure_mutation_allowed()
            self._cleanup(db,now)
            previous=db.execute('SELECT * FROM binding_operations WHERE operation_id=?',(operation_id,)).fetchone()
            if previous is not None:
                if not hmac.compare_digest(previous['secret_hash'],digest(secret)) or previous['request_hash']!=request_hash:
                    raise ConflictError('Operation identity reused')
                return self._state(db,previous,now)
            row=db.execute('SELECT * FROM clients WHERE code_hash=?',(digest(code),)).fetchone()
            if row is None or not row['issued']<=now<row['expires']: raise ValueError('Invalid or expired invitation')
            if expected_client_id is not None and expected_client_id!=row['id']:
                raise BoundDomainError('Wrong connection',reason='wrong_connection')
            if row['status_secret_hash']==digest(secret): raise ValueError('A new secret is required')
            bound=_has_binding(db,row)
            transfer=self.store._transfer_code(db,row)
            if bound and not transfer and not (expected_client_id==row['id'] and binding_secret and row['status_secret_hash'] and hmac.compare_digest(digest(binding_secret),row['status_secret_hash'])):
                raise BoundDomainError('Domain is bound')
            if reserved(db,row,now): raise ConflictError('Invitation reserved')
            if db.execute('SELECT count(*) FROM binding_operations').fetchone()[0]>=MAX_RECORDS:
                raise ConflictError('Enrollment capacity exhausted; retry later')
            expires=min(row['expires'],now+900)
            db.execute('INSERT INTO binding_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (operation_id,row['id'],row['domain'],digest(secret),request_hash,row['code_hash'],row['generation'],row['revision'],row['generation']+int(bound or transfer),int(transfer),expires,now+REPLAY_SECONDS,'prepared'))
            return self._state(db,self._row(db,operation_id,row['id'],secret),now)

    def status(self, operation_id, client_id, secret, now):
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self.store.ensure_mutation_allowed()
            self._cleanup(db,now)
            return self._state(db,self._row(db,operation_id,client_id,secret),now)

    def cancel(self, operation_id, client_id, secret, now):
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self.store.ensure_mutation_allowed()
            op=self._row(db,operation_id,client_id,secret)
            if op['state']=='prepared':
                db.execute("UPDATE binding_operations SET state='cancelled' WHERE operation_id=?",(operation_id,))
            return self._state(db,self._row(db,operation_id,client_id,secret),now)

    def commit(self, operation_id, client_id, secret, now):
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self.store.ensure_mutation_allowed()
            self._cleanup(db,now)
            op=self._row(db,operation_id,client_id,secret)
            result=self._state(db,op,now)
            if result['state']=='committed': return result
            if result['state']!='prepared' or self.store.migrating: raise ConflictError('Reservation changed or expired')
            original=db.execute('SELECT * FROM clients WHERE id=?',(client_id,)).fetchone()
            initially_unbound=not _has_binding(db,original)
            # All invitation, policy, domain and generation checks above share this write transaction.
            db.execute('''UPDATE clients SET code_hash=NULL,code_ciphertext=NULL,secret_hash=?,status_secret_hash=?,
                revoked=0,generation=?,revision=revision+1,traffic_started_at=COALESCE(traffic_started_at,?) WHERE id=?''',
                (op['secret_hash'],op['secret_hash'],op['target_generation'],now,client_id))
            if initially_unbound:
                updated=db.execute('SELECT * FROM clients WHERE id=?',(client_id,)).fetchone()
                self.store.reconcile_billing(db,updated,now)
            db.execute('DELETE FROM server_metadata WHERE name=?',('invitation_transfer:'+client_id,))
            db.execute('INSERT OR REPLACE INTO server_metadata VALUES (?,?)',('binding_claimed:'+client_id,'true'))
            db.execute("UPDATE binding_operations SET state='committed',retain_until=? WHERE operation_id=?",(now+REPLAY_SECONDS,operation_id))
            append_event(db,action='transfer' if op['transfer'] else 'redeem',actor=Actor('client'),client_id=client_id,domain=op['domain'],at=now)
            result=self._state(db,self._row(db,operation_id,client_id,secret),now)
        self.store.admission.remove(client_id)
        return result
