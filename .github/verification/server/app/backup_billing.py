"""Strict portable validation/import for monetary state; never downgrade it to legacy format."""
import json
import math
import re
from server.app.subscription import money_integer, Period, zone
from server.app.journal import Actor

OP_FIELDS=('operation_id','client_id','kind','at','delta_kopecks','balance_before','balance_after',
    'price_kopecks','paid_from','paid_until','actor','details')
KINDS={'set_price','topup','set_balance','purchase','compensation'}


def validate_subscription(row):
    if row['billing_mode'] not in ('free','legacy','monthly'): raise ValueError()
    money_integer(row['price_kopecks']); money_integer(row['balance_kopecks'],negative=True)
    if type(row['billing_paused']) is not int or row['billing_paused'] not in (0,1): raise ValueError()
    zone(row['billing_timezone'])
    if (row['paid_from'] is None)!=(row['paid_until'] is None): raise ValueError()
    if row['paid_until'] is not None: Period(row['paid_from'],row['paid_until'],row['anchor_day'],row['billing_timezone'])
    elif row['anchor_day'] is not None: raise ValueError()
    if row['billing_mode']=='monthly':
        if row['duration'] is not None: raise ValueError()
        expected=row['paid_until'] if row['price_kopecks']>0 else None
        if row['deadline']!=expected: raise ValueError()
    elif row['price_kopecks']!=0: raise ValueError()


def restore_financial(db,payload):
    operations,commands=payload['billing_operations'],payload['billing_commands']
    if not isinstance(operations,list) or not isinstance(commands,list) or len(operations)>100000 or len(commands)>100000:
        raise ValueError()
    for row in operations:
        if not isinstance(row,dict) or set(row)!=set(OP_FIELDS): raise ValueError()
        if not isinstance(row['operation_id'],str) or not 1<=len(row['operation_id'])<=256: raise ValueError()
        if not isinstance(row['client_id'],str) or not re.fullmatch('[a-f0-9]{32}',row['client_id']) or row['kind'] not in KINDS: raise ValueError()
        for name in ('delta_kopecks','balance_before','balance_after'):
            money_integer(row[name],negative=True)
        money_integer(row['price_kopecks'])
        if row['balance_before']+row['delta_kopecks']!=row['balance_after']: raise ValueError()
        if type(row['at']) not in (int,float) or not math.isfinite(row['at']) or row['at']<0: raise ValueError()
        actor,details=json.loads(row['actor']),json.loads(row['details'])
        if not isinstance(actor,dict) or set(actor)!={'source','user_id'} or actor['source'] not in ('system','timer','web','client','mqtt'): raise ValueError()
        if actor['user_id'] is not None and (not isinstance(actor['user_id'],str) or len(actor['user_id'])>128): raise ValueError()
        if not isinstance(details,dict) or set(details)-{'timezone','anchor_day','days'}: raise ValueError()
        zone(details['timezone'])
        if 'days' in details and (type(details['days']) is not int or not 0<=details['days']<=2**31-1): raise ValueError()
        if (row['paid_from'] is None)!=(row['paid_until'] is None): raise ValueError()
        if row['paid_until'] is not None: Period(row['paid_from'],row['paid_until'],details['anchor_day'],details['timezone'])
        elif details['anchor_day'] is not None: raise ValueError()
        db.execute('INSERT INTO billing_operations ('+','.join(OP_FIELDS)+') VALUES ('+','.join('?' for _ in OP_FIELDS)+')',tuple(row[k] for k in OP_FIELDS))
    for item in commands:
        if not isinstance(item,dict) or set(item)!={'client_id','command_id','request','result'}: raise ValueError()
        if not db.execute('SELECT 1 FROM clients WHERE id=?',(item['client_id'],)).fetchone(): raise ValueError()
        if not isinstance(item['command_id'],str) or not 1<=len(item['command_id'])<=128: raise ValueError()
        request,result=json.loads(item['request']),json.loads(item['result'])
        if not isinstance(request,list) or len(request)!=4 or request[0] not in KINDS-{'purchase','compensation'}: raise ValueError()
        if type(request[1]) is not int or request[1]<0: raise ValueError()
        money_integer(request[2],negative=request[0]=='set_balance'); zone(request[3])
        validate_command_result(result,item['client_id'])
        if request[0]=='topup' and request[2]<=0: raise ValueError()
        operation=db.execute('SELECT kind FROM billing_operations WHERE operation_id=?',(f"manual:{item['client_id']}:{item['command_id']}",)).fetchone()
        if not operation or operation['kind']!=request[0]: raise ValueError()
        if set(result)&{'secret','code','invitation','secret_hash','status_secret_hash','code_ciphertext'}: raise ValueError()
        db.execute('INSERT INTO billing_commands VALUES (?,?,?,?)',tuple(item[n] for n in ('client_id','command_id','request','result')))

SNAPSHOT_FIELDS={'client_id','id','domain','enrolled','revoked','paused','expired','access_state',
    'deadline','duration','billing','timezone','revision','generation','capabilities','editable',
    'to_client_bytes','from_client_bytes','traffic_started_at','last_seen','issued','expires'}

def validate_command_result(result,client_id):
    from shared.billing_status import validate_billing
    from shared.validation import domain
    from server.app.duration import parse_duration
    from server.app.subscription import instant
    if not isinstance(result,dict) or set(result)!=SNAPSHOT_FIELDS or result['client_id']!=client_id or result['id']!=client_id: raise ValueError()
    domain(result['domain']); zone(result['timezone'])
    for field in ('enrolled','revoked','paused','expired','editable'):
        if type(result[field]) is not bool: raise ValueError()
    for field in ('revision','generation','to_client_bytes','from_client_bytes'):
        money_integer(result[field])
    if result['access_state'] not in ('allowed','paused','expired','revoked','pending','clock_error'): raise ValueError()
    caps=result['capabilities']
    if not isinstance(caps,list) or len(caps)>2 or any(v not in ('access-v1','telemetry-v1') for v in caps): raise ValueError()
    for field in ('deadline','traffic_started_at','last_seen','issued','expires'):
        if result[field] is not None: instant(result[field])
    if result['duration'] is not None: parse_duration(result['duration'])
    billing=result['billing']
    if not isinstance(billing,dict) or 'updated_at' in billing: raise ValueError()
    validate_billing(dict(billing,updated_at=0))

def restore_availability(db,payload):
    from server.app.subscription import instant, compensation_days
    availability=payload['availability']
    if not isinstance(availability,dict) or set(availability)!={'episodes','entitlements'}: raise ValueError()
    episodes,entitlements=availability['episodes'],availability['entitlements']
    if not isinstance(episodes,list) or not isinstance(entitlements,list) or len(episodes)>100000 or len(entitlements)>100000: raise ValueError()
    for row in episodes:
        if not isinstance(row,dict) or set(row)!={'id','started_at','ended_at','compensated_days','state'}: raise ValueError()
        if not isinstance(row['id'],str) or not re.fullmatch('[a-f0-9]{32}',row['id']): raise ValueError()
        instant(row['started_at'])
        if type(row['compensated_days']) is not int or row['compensated_days']<0: raise ValueError()
        state=row['state']
        if state not in ('open','closed','imported'): raise ValueError()
        if state=='open':
            if row['ended_at'] is not None or row['compensated_days']!=0: raise ValueError()
        else:
            instant(row['ended_at'])
            if row['ended_at']<row['started_at']: raise ValueError()
            if state=='closed' and compensation_days(row['ended_at']-row['started_at'])!=row['compensated_days']: raise ValueError()
        db.execute('INSERT INTO outage_episodes VALUES (?,?,?,?,?)',tuple(row[name] for name in ('id','started_at','ended_at','compensated_days','state')))
    for row in entitlements:
        if not isinstance(row,dict) or set(row)!={'episode_id','client_id','paid_until_at_start','eligible'}: raise ValueError()
        if not isinstance(row['client_id'],str) or not re.fullmatch('[a-f0-9]{32}',row['client_id']): raise ValueError()
        if not db.execute('SELECT 1 FROM outage_episodes WHERE id=?',(row['episode_id'],)).fetchone(): raise ValueError()
        if type(row['eligible']) is not int or row['eligible'] not in (0,1): raise ValueError()
        instant(row['paid_until_at_start'])
        db.execute('INSERT INTO outage_entitlements VALUES (?,?,?,?)',tuple(row[name] for name in ('episode_id','client_id','paid_until_at_start','eligible')))
    # Portable copies retain history but never compensate their age on another host.
    import time
    db.execute("UPDATE outage_episodes SET state='imported',ended_at=MAX(started_at,?),compensated_days=0 WHERE state='open'",(time.time(),))
    db.execute('DELETE FROM availability_checkpoint')
    db.execute("DELETE FROM server_metadata WHERE name IN ('service_last_healthy','service_shutdown_at')")
