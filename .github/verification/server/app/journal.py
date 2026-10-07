"""Durable, bounded audit reads; credentials never enter event payloads."""
import csv
import io
import json
import math
import secrets
import re
from pathlib import Path
from shared.files import atomic_write
from dataclasses import dataclass
from contextvars import ContextVar

current_actor = ContextVar('audit_actor', default=None)


@dataclass(frozen=True)
class Actor:
    source: str
    user_id: str | None = None


def append_event(db, *, action, actor=None, client_id=None, domain=None,
                 result='success', at, details=None, operation_id=None):
    actor = actor or current_actor.get() or Actor('system')
    if actor.source not in ('web', 'mqtt', 'client', 'timer', 'system'):
        raise ValueError('Invalid audit source')
    if result not in ('success', 'requested', 'error', 'unknown') or not math.isfinite(at):
        raise ValueError('Invalid audit result/time')
    if not isinstance(action, str) or not 1 <= len(action) <= 64:
        raise ValueError('Invalid audit action')
    # Only bounded non-secret fields from our own templates, never raw exceptions/requests.
    safe = {}
    for name in ('balance_kopecks','price_kopecks','delta_kopecks','days'):
        value=(details or {}).get(name)
        if type(value) is int and -(2**63)<=value<2**63: safe[name]=value
    for name in ('deadline', 'paid_until', 'available', 'count', 'reason', 'revision', 'duration', 'timezone'):
        value = (details or {}).get(name)
        if name == 'reason' and value not in ('invalid_request', 'unavailable', 'interrupted', 'storage_error'):
            continue
        if value is not None and isinstance(value, (str, int, float, bool)):
            safe[name] = value[:128] if isinstance(value, str) else value
    return db.execute('''INSERT INTO audit_events
        (at,action,source,user_id,client_id,domain,result,details,operation_id)
        VALUES (?,?,?,?,?,?,?,?,?)''',
        (at, action, actor.source, (actor.user_id or '')[:128] or None,
         client_id, domain, result, json.dumps(safe, ensure_ascii=False), operation_id)).lastrowid


class Journal:
    def __init__(self, store,*,operations_path=None):
        self.store=store
        self.operations_path=Path(operations_path) if operations_path else store.path.with_name('operations.pending.json')

    def pending(self):
        if not self.operations_path.exists(): return {}
        if self.operations_path.stat().st_size>131072: raise ValueError('Operation marker too large')
        data=json.loads(self.operations_path.read_bytes())
        if not isinstance(data,dict) or len(data)>32: raise ValueError('Invalid operation markers')
        return data

    def request(self,action,at,*,actor=None):
        pending=self.pending()
        if len(pending)>=32: raise ValueError('Too many pending operations')
        operation='op:'+secrets.token_hex(16)
        event=self.record(action,at,actor=actor,result='requested',operation_id=operation+':requested')
        with self.store.connection() as db:
            pending[operation]=dict(db.execute('SELECT * FROM audit_events WHERE id=?',(event,)).fetchone())
        atomic_write(self.operations_path,json.dumps(pending).encode())
        return operation

    def finish(self,operation,result,at):
        if not re.fullmatch(r'op:[a-f0-9]{32}',operation) or result not in ('success','error','unknown'): raise ValueError('Invalid operation result')
        pending=self.pending()
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            terminal=db.execute('SELECT id FROM audit_events WHERE operation_id IN (?,?,?)',
                tuple(operation+':'+phase for phase in ('success','error','unknown'))).fetchone()
            if not terminal:
                row=db.execute('SELECT * FROM audit_events WHERE operation_id=?',(operation+':requested',)).fetchone()
                original=dict(row) if row else pending.get(operation)
                if original is None: raise ValueError('Unknown operation')
                actor=Actor(original['source'],original['user_id'])
                details=json.loads(original['details'])
                if not row:
                    append_event(db,action=original['action'],actor=actor,at=original['at'],result='requested',
                        client_id=original['client_id'],domain=original['domain'],details=details,operation_id=operation+':requested')
                append_event(db,action=original['action'],actor=actor,at=at,result=result,
                    client_id=original['client_id'],domain=original['domain'],details={'reason':'interrupted'} if result=='unknown' else None,
                    operation_id=operation+':'+result)
        if operation in pending:
            pending.pop(operation)
            atomic_write(self.operations_path,json.dumps(pending).encode())

    def record(self, action, at, *, actor=None, client_id=None, result='success', details=None, operation_id=None):
        with self.store.connection() as db:
            row = db.execute('SELECT domain FROM clients WHERE id=?', (client_id,)).fetchone() if client_id else None
            return append_event(db, action=action, at=at, actor=actor, client_id=client_id,
                domain=row['domain'] if row else None, result=result, details=details, operation_id=operation_id)

    def page(self, *, before_id=None, limit=50, client_id=None, action=None,
             result=None, since=None, until=None):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Invalid page size')
        where, args = [], []
        if before_id is not None:
            if type(before_id) is not int or before_id < 1: raise ValueError('Invalid cursor')
            where.append('id < ?'); args.append(before_id)
        for name, value in (('client_id', client_id), ('action', action), ('result', result)):
            if value is not None:
                if not isinstance(value, str) or len(value) > 128: raise ValueError('Invalid filter')
                where.append(name+' = ?'); args.append(value)
        for op, value in (('>=', since), ('<=', until)):
            if value is not None:
                if not isinstance(value, (int, float)) or not math.isfinite(value): raise ValueError('Invalid date')
                where.append('at '+op+' ?'); args.append(value)
        clause = ' WHERE '+' AND '.join(where) if where else ''
        with self.store.connection() as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM audit_events'+clause+' ORDER BY id DESC LIMIT ?', (*args, limit+1))]
        more = len(rows) > limit
        rows = rows[:limit]
        for row in rows: row['details'] = json.loads(row['details'])
        return {'items': rows, 'next_cursor': rows[-1]['id'] if more else None}

    def catalog(self):
        with self.store.connection() as db:
            clients=[dict(row) for row in db.execute('''SELECT c.id AS client_id,c.domain,0 AS deleted,c.revoked
                FROM clients c UNION ALL SELECT a.client_id,MAX(a.domain),1,1 FROM audit_events a
                WHERE a.client_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM clients c WHERE c.id=a.client_id)
                GROUP BY a.client_id ORDER BY domain,client_id''')]
            actions=[row[0] for row in db.execute('SELECT DISTINCT action FROM audit_events ORDER BY action')]
            count,size=db.execute('''SELECT COUNT(*),COALESCE(SUM(64+length(CAST(action||source||
                COALESCE(user_id,'')||COALESCE(client_id,'')||COALESCE(domain,'')||result||details||
                COALESCE(operation_id,'') AS BLOB))),0) FROM audit_events''').fetchone()
        return {'clients':clients,'actions':actions,'events':count,'estimated_bytes':size}

    def csv(self, filters):
        def line(values):
            stream = io.StringIO(newline='')
            safe = []
            for value in values:
                text = str(value) if value is not None else ''
                safe.append("'"+text if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else text)
            csv.writer(stream).writerow(safe)
            return stream.getvalue()
        yield line(['ID', 'Время UTC', 'Действие', 'Источник', 'Пользователь', 'Подключение', 'Домен', 'Результат', 'Подробности'])
        cursor = None
        while True:
            page = self.page(**filters, before_id=cursor, limit=100)
            for row in page['items']:
                yield line([row[k] for k in ('id', 'at', 'action', 'source', 'user_id', 'client_id', 'domain', 'result')]+[json.dumps(row['details'], ensure_ascii=False)])
            cursor = page['next_cursor']
            if cursor is None: break

    def transition(self, client_id, action, available, at):
        if action not in ('ha_available', 'frp_connected'): raise ValueError('Invalid transition')
        key = 'audit:'+action+':'+client_id
        value = json.dumps(bool(available))
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT value FROM server_metadata WHERE name=?', (key,)).fetchone()
            if old and old['value'] == value: return False
            row = db.execute('SELECT domain FROM clients WHERE id=?', (client_id,)).fetchone()
            if not row: return False
            append_event(db, action=action, client_id=client_id, domain=row['domain'], at=at, details={'available': bool(available)})
            db.execute('INSERT OR REPLACE INTO server_metadata VALUES (?,?)', (key, value))
        return True

    def startup(self, at):
        pending=set(self.pending())
        with self.store.connection() as db:
            pending.update(row['operation_id'].removesuffix(':requested') for row in db.execute(
                "SELECT operation_id FROM audit_events WHERE operation_id LIKE 'op:%:requested' AND NOT EXISTS (SELECT 1 FROM audit_events done WHERE done.operation_id IN (substr(audit_events.operation_id,1,length(audit_events.operation_id)-9)||'success',substr(audit_events.operation_id,1,length(audit_events.operation_id)-9)||'error',substr(audit_events.operation_id,1,length(audit_events.operation_id)-9)||'unknown'))"))
        for operation in pending: self.finish(operation,'unknown',at)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute("SELECT value FROM server_metadata WHERE name='audit_running'").fetchone()
            if old and old['value'] == 'true':
                append_event(db, action='unclean_shutdown', result='unknown', at=at, details={'reason': 'interrupted'})
            append_event(db, action='startup', at=at)
            db.execute("INSERT OR REPLACE INTO server_metadata VALUES ('audit_running','true')")

    def shutdown(self, at):
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            append_event(db, action='shutdown', at=at)
            db.execute("INSERT OR REPLACE INTO server_metadata VALUES ('audit_running','false')")
