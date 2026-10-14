"""Exclusive, audited clock repair; original money and purchases are immutable."""
import hashlib
import json
import re
from server.app.store import ConflictError
from server.app.journal import append_event, Actor
from server.app.subscription import first_period, instant, zone, Period, _midnight


def reconciled_period(start, end, timezone):
    local=instant(end).astimezone(zone(timezone))
    original=first_period(start,timezone)
    if end!=_midnight(local.date(),local.tzinfo): raise ValueError('End must be the canonical local calendar boundary')
    anchor=original.anchor_day if end==original.end else local.day
    return Period(start,end,anchor,timezone)


def validate_correction(reason, operation_ids):
    if not isinstance(reason,str) or not 1<=len(reason.strip())<=500: raise ValueError('Reason required')
    if not isinstance(operation_ids,list) or not operation_ids or len(operation_ids)>10000 or any(not isinstance(i,str) or not 1<=len(i)<=256 for i in operation_ids) or len(set(operation_ids))!=len(operation_ids):
        raise ValueError('Original purchase operations required')


def metadata(db, name, value):
    db.execute('INSERT OR REPLACE INTO server_metadata VALUES (?,?)',(name,json.dumps(value,ensure_ascii=False)))


def financial_revision(db, clock):
    snapshot = {}
    for table, order in (('clients','id'),('billing_operations','operation_id'),('billing_commands','client_id,command_id'),
                         ('access_commands','client_id,command_id'),('outage_episodes','id'),
                         ('outage_entitlements','episode_id,client_id'),('availability_checkpoint','client_id')):
        rows = [dict(r) for r in db.execute('SELECT * FROM '+table+' ORDER BY '+order)]
        if table=='clients':
            for row in rows:
                for key in ('last_seen','to_client_bytes','from_client_bytes','traffic_started_at','code_ciphertext'): row.pop(key,None)
        snapshot[table] = rows
    snapshot['metadata'] = [dict(r) for r in db.execute("SELECT * FROM server_metadata WHERE name='instance_id' OR (name GLOB 'clock_*' AND name!='clock_anchor') ORDER BY name")]
    if not db.execute("SELECT 1 FROM server_metadata WHERE name='clock_financial_anchor'").fetchone():
        snapshot['unrepaired_anchor'] = [dict(r) for r in db.execute("SELECT * FROM server_metadata WHERE name='clock_anchor'")]
    snapshot['live_proof'] = clock.confirmed_snapshot()
    snapshot['live_reliable'] = clock.reliable
    return hashlib.sha256(json.dumps(snapshot,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def reset_baseline(db, now):
    # Ambiguous episodes retain evidence but never generate compensation.
    db.execute("UPDATE outage_episodes SET state='imported',ended_at=MAX(started_at,?),compensated_days=0 WHERE state='open'",(now,))
    db.execute('DELETE FROM availability_checkpoint')
    db.execute("DELETE FROM server_metadata WHERE name IN ('service_shutdown_at','clock_ambiguous')")
    metadata(db,'service_last_healthy',now)


class ClockRepair:
    def __init__(self, store, clock):
        self.store, self.clock = store, clock

    def preview(self):
        proof = self.clock.confirmed_snapshot()
        now = self.clock.now()
        with self.store.connection() as db:
            db.execute('BEGIN')
            clients = []
            for row in db.execute('SELECT * FROM clients ORDER BY id'):
                hold = db.execute('SELECT value FROM server_metadata WHERE name=?',('clock_hold:'+row['id'],)).fetchone()
                if row['paid_from'] is not None:
                    clients.append({'client_id':row['id'],'domain':row['domain'],'balance_kopecks':row['balance_kopecks'],
                        'paid_from':row['paid_from'],'paid_until':row['paid_until'],'timezone':row['billing_timezone'],
                        'hold':bool(hold) or row['paid_from']>now,'operation_ids':[r[0] for r in db.execute("SELECT operation_id FROM billing_operations WHERE client_id=? AND kind='purchase' ORDER BY operation_id",(row['id'],))]})
            old_anchor=self.store.get_metadata('clock_anchor',0)
            return {'revision':financial_revision(db,self.clock),'old_anchor':old_anchor,
                    'repair_allowed':self.clock.repair_allowed(old_anchor),
                    'confirmed_snapshot':proof,'confirmed_now':self.clock.confirmed_now(proof) if proof else None,
                    'reliable':self.clock.reliable,'clients':clients}

    def _request(self, command_id, revision, payload):
        if not isinstance(command_id,str) or not 1<=len(command_id)<=128: raise ValueError('Invalid command identifier')
        if not isinstance(revision,str) or not re.fullmatch('[a-f0-9]{64}',revision): raise ValueError('Financial revision required')
        key = 'clock_command:'+hashlib.sha256(command_id.encode()).hexdigest()
        request = hashlib.sha256(json.dumps([revision,payload],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return key,request

    def _begin(self, db, key, request, revision):
        db.execute('BEGIN IMMEDIATE')
        self.store.ensure_mutation_allowed()
        prior = db.execute('SELECT value FROM server_metadata WHERE name=?',(key,)).fetchone()
        if prior:
            receipt=json.loads(prior[0])
            if receipt['request']!=request: raise ConflictError('Command identifier was reused')
            return receipt['result']
        if financial_revision(db,self.clock)!=revision: raise ConflictError('Financial preview is stale')
        return None

    async def repair(self, command_id, expected_revision, confirmed_snapshot, *, actor=None):
        key,request = self._request(command_id,expected_revision,['repair',confirmed_snapshot])
        async with self.store.administration.exclusive('clock_repair'):
            with self.store.connection() as db:
                previous=self._begin(db,key,request,expected_revision)
                if previous is not None: return previous
                now=self.clock.confirmed_now(confirmed_snapshot)
                old=self.store.get_metadata('clock_anchor',0)
                if not self.clock.repair_allowed(old): raise ConflictError('Clock anchor does not require rollback')
                for row in db.execute('SELECT id,paid_from FROM clients WHERE paid_from>?',(now,)).fetchall():
                    metadata(db,'clock_hold:'+row['id'],True)
                reset_baseline(db,now)
                metadata(db,'clock_anchor',now)
                metadata(db,'clock_financial_anchor',now)
                metadata(db,'clock_proof',confirmed_snapshot)
                result={'old_anchor':old,'new_anchor':now}
                append_event(db,action='clock_repair',at=now,actor=actor,operation_id=key,
                             details={'deadline':old,'paid_until':now})
                metadata(db,key,{'request':request,'result':result})
            self.clock.accept_repair(now)
            return result

    def _period_context(self, db, client_id, period, operation_ids):
        now=self.clock.now()
        if not self.clock.reliable or not period.start<=now<period.end: raise ConflictError('Period must cover confirmed current time')
        row=db.execute('SELECT * FROM clients WHERE id=?',(client_id,)).fetchone()
        if row is None or (not db.execute('SELECT 1 FROM server_metadata WHERE name=?',('clock_hold:'+client_id,)).fetchone() and not (row['paid_from'] is not None and row['paid_from']>now)):
            raise ConflictError('No period hold to reconcile')
        originals=[r[0] for r in db.execute("SELECT operation_id FROM billing_operations WHERE client_id=? AND kind='purchase' ORDER BY operation_id",(client_id,))]
        if sorted(operation_ids)!=originals: raise ConflictError('Confirm the original purchase operations')
        return row,now

    def preview_period(self, client_id, expected_revision, paid_from, paid_until, timezone, reason, operation_ids):
        validate_correction(reason,operation_ids)
        period=reconciled_period(paid_from,paid_until,timezone)
        self.store.ensure_mutation_allowed()
        with self.store.connection() as db:
            db.execute('BEGIN')
            revision=financial_revision(db,self.clock)
            if expected_revision!=revision: raise ConflictError('Financial preview is stale')
            row,now=self._period_context(db,client_id,period,operation_ids)
            return {'revision':revision,'client_id':client_id,'balance_kopecks':row['balance_kopecks'],
                'old_period':{'paid_from':row['paid_from'],'paid_until':row['paid_until'],'timezone':row['billing_timezone'],'anchor_day':row['anchor_day']},
                'new_period':{'paid_from':paid_from,'paid_until':paid_until,'timezone':timezone,'anchor_day':period.anchor_day},
                'reason':reason,'operation_ids':operation_ids}

    async def reconcile_period(self, client_id, command_id, expected_revision, paid_from, paid_until, timezone, reason, operation_ids, *, actor=None):
        validate_correction(reason,operation_ids)
        period=reconciled_period(paid_from,paid_until,timezone)
        key,request=self._request(command_id,expected_revision,['period',client_id,paid_from,paid_until,timezone,reason,operation_ids])
        async with self.store.administration.exclusive('period_reconciliation'):
            with self.store.connection() as db:
                previous=self._begin(db,key,request,expected_revision)
                if previous is not None: return previous
                row,now=self._period_context(db,client_id,period,operation_ids)
                details={'timezone':timezone,'anchor_day':period.anchor_day,'reason':reason,
                         'old_period':{'paid_from':row['paid_from'],'paid_until':row['paid_until'],'timezone':row['billing_timezone'],'anchor_day':row['anchor_day']},
                         'operation_ids':operation_ids}
                db.execute("UPDATE clients SET paid_from=?,paid_until=?,anchor_day=?,billing_timezone=?,billing_paused=0,deadline=CASE WHEN price_kopecks>0 THEN ? ELSE NULL END,revision=revision+1 WHERE id=?",
                           (paid_from,paid_until,period.anchor_day,timezone,paid_until,client_id))
                who=actor or Actor('system')
                db.execute('INSERT INTO billing_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                           (key,client_id,'period_correction',now,0,row['balance_kopecks'],row['balance_kopecks'],row['price_kopecks'],paid_from,paid_until,
                            json.dumps({'source':who.source,'user_id':who.user_id}),json.dumps(details,ensure_ascii=False)))
                db.execute('DELETE FROM server_metadata WHERE name=?',('clock_hold:'+client_id,))
                append_event(db,action='period_correction',at=now,actor=actor,client_id=client_id,domain=row['domain'],operation_id=key,
                             details={'delta_kopecks':0,'paid_until':paid_until})
                result={'client_id':client_id,'paid_from':paid_from,'paid_until':paid_until,'balance_kopecks':row['balance_kopecks']}
                metadata(db,key,{'request':request,'result':result})
                return result


def validate_metadata(db, name, value):
    """Portable proof is history only; it never supplies live synchronization."""
    if name=='clock_financial_anchor':
        instant(value)
        if value<0: raise ValueError()
    elif name=='clock_ambiguous':
        if value is not True: raise ValueError()
    elif name=='clock_proof':
        if not isinstance(value,dict) or set(value)!={'id','at'} or not isinstance(value['id'],str) or not re.fullmatch('[a-f0-9]{32}',value['id']): raise ValueError()
        instant(value['at'])
        if value['at']<0: raise ValueError()
    elif re.fullmatch('clock_hold:[a-f0-9]{32}',name):
        if value is not True or not db.execute('SELECT 1 FROM clients WHERE id=?',(name.split(':')[1],)).fetchone(): raise ValueError()
    elif re.fullmatch('clock_command:[a-f0-9]{64}',name):
        if not isinstance(value,dict) or set(value)!={'request','result'} or not isinstance(value['request'],str) or not re.fullmatch('[a-f0-9]{64}',value['request']): raise ValueError()
        result=value['result']
        if not isinstance(result,dict): raise ValueError()
        if set(result)=={'old_anchor','new_anchor'}:
            instant(result['old_anchor']); instant(result['new_anchor'])
            if not 0<=result['new_anchor']<result['old_anchor']: raise ValueError()
        elif set(result)=={'client_id','paid_from','paid_until','balance_kopecks'}:
            from server.app.subscription import money_integer
            if not isinstance(result['client_id'],str) or not re.fullmatch('[a-f0-9]{32}',result['client_id']): raise ValueError()
            instant(result['paid_from']); instant(result['paid_until']); money_integer(result['balance_kopecks'],negative=True)
            if not result['paid_from']<result['paid_until']: raise ValueError()
        else: raise ValueError()
    else: raise ValueError()


def validate_receipts(db):
    """A portable replay result must name its committed audit and cash-neutral row."""
    for item in db.execute("SELECT name,value FROM server_metadata WHERE name GLOB 'clock_command:*'"):
        result=json.loads(item['value'])['result']
        audit=db.execute('SELECT * FROM audit_events WHERE operation_id=?',(item['name'],)).fetchone()
        if audit is None or audit['result']!='success': raise ValueError('Clock receipt has no committed audit')
        if 'old_anchor' in result:
            details=json.loads(audit['details'])
            if audit['action']!='clock_repair' or details.get('deadline')!=result['old_anchor'] or details.get('paid_until')!=result['new_anchor'] or audit['at']!=result['new_anchor']:
                raise ValueError('Clock repair result differs from audit')
        else:
            row=db.execute('SELECT * FROM billing_operations WHERE operation_id=?',(item['name'],)).fetchone()
            if row is None or row['kind']!='period_correction' or audit['action']!='period_correction' or audit['client_id']!=result['client_id'] or row['delta_kopecks']!=0:
                raise ValueError('Period receipt has no neutral correction')
            for name in ('client_id','paid_from','paid_until'):
                if row[name]!=result[name]: raise ValueError('Period result differs from correction')
            if row['balance_after']!=result['balance_kopecks']: raise ValueError('Period result changes the balance')
