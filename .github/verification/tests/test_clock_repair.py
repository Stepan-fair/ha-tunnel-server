import sys
import pytest
from server.app.clock import SafeClock
from server.app.store import Store, ConflictError
from tests.test_billing_store import funded, operations, command

class Time:
    def __init__(self, wall=1790000000): self.wall,self.mono=wall,0
    def advance(self, seconds): self.wall+=seconds; self.mono+=seconds
    def clock(self, anchor=0): return SafeClock(lambda:self.wall,lambda:self.mono,anchor)
    def confirm(self, clock):
        for _ in range(3):
            clock.observe_host({'dt_synchronized':True})
            if _<2: self.advance(10)


def test_boot_needs_fresh_proof_and_never_checkpoints_wall():
    t=Time(); clock=t.clock()
    assert not clock.reliable
    assert clock.checkpoint()==0
    t.confirm(clock)
    assert clock.reliable and clock.checkpoint()==t.wall
    assert not t.clock(clock.checkpoint()).reliable

@pytest.mark.parametrize('restart',[False,True])
def test_forward_jump_and_correction_never_poison_anchor(restart):
    t=Time(); clock=t.clock(); t.confirm(clock); saved=clock.checkpoint()
    t.wall+=90*86400
    assert not clock.reliable
    assert clock.checkpoint()==saved
    if restart: clock=t.clock(clock.checkpoint())
    t.wall-=90*86400
    t.confirm(clock)
    assert clock.reliable and clock.now()==t.wall

@pytest.mark.parametrize('bad',[False,None,1,'true',{},[]])
def test_ntp_proof_requires_exact_true(bad):
    t=Time(); clock=t.clock()
    for _ in range(4): clock.observe_host({'dt_synchronized':bad}); t.advance(10)
    assert not clock.reliable and clock.checkpoint()==0


def test_fast_and_unstable_observations_do_not_confirm():
    t=Time(); clock=t.clock()
    for _ in range(4): clock.observe_host({'dt_synchronized':True}); t.advance(1)
    assert not clock.reliable
    t.advance(10); t.wall+=2; clock.observe_host({'dt_synchronized':True})
    assert not clock.reliable
    t.confirm(clock); assert clock.reliable


def test_real_elapsed_outage_is_not_a_jump():
    t=Time(); clock=t.clock(); t.confirm(clock)
    t.advance(90*86400)
    assert clock.reliable and clock.now()==t.wall


@pytest.mark.asyncio
async def test_poisoned_anchor_repair_hold_and_neutral_reconciliation(tmp_path):
    from server.app.clock_repair import ClockRepair
    store,creds,repo,wall,before=funded(tmp_path)
    original=operations(store)
    t=Time(wall[0]-90*86400); clock=t.clock(wall[0]); store.clock=clock
    store.set_metadata('clock_anchor',wall[0]); t.confirm(clock)
    repair=ClockRepair(store,clock)
    preview=repair.preview()
    assert not clock.reliable and preview['confirmed_snapshot'] is not None
    assert preview['repair_allowed'] is True
    args=('repair-one',preview['revision'],preview['confirmed_snapshot'])
    result=await repair.repair(*args)
    assert await repair.repair(*args)==result
    assert operations(store)==original and clock.reliable
    assert store.access_snapshot(creds.client_id,t.wall)['access_state']=='clock_error'
    command(repo,creds.client_id,'set_balance',90000,t.wall)
    assert len(operations(store,'purchase'))==1
    reopened=Store(store.path,'example.org',clock=clock)
    assert reopened.access_snapshot(creds.client_id,t.wall)['access_state']=='clock_error'
    preview=repair.preview()
    from server.app.subscription import first_period
    period=first_period(t.wall-60,'UTC')
    ids=[r['operation_id'] for r in original if r['kind']=='purchase']
    await repair.reconcile_period(creds.client_id,'reconcile-one',preview['revision'],period.start,period.end,'UTC','Исправление даты',ids)
    assert store.access_snapshot(creds.client_id,t.wall)['access_state']=='allowed'
    corrections=operations(store,'period_correction')
    assert len(corrections)==1 and corrections[0]['delta_kopecks']==0
    assert len(operations(store,'purchase'))==1


async def poisoned(tmp_path):
    from server.app.clock_repair import ClockRepair
    store,creds,repo,wall,before=funded(tmp_path)
    t=Time(wall[0]-90*86400); clock=t.clock(wall[0]); store.clock=clock
    store.set_metadata('clock_anchor',wall[0]); t.confirm(clock)
    return store,creds,repo,t,clock,ClockRepair(store,clock)

@pytest.mark.asyncio
async def test_stale_whole_financial_snapshot_and_command_conflict(tmp_path):
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    preview=repair.preview()
    with store.connection() as db: db.execute('UPDATE clients SET balance_kopecks=balance_kopecks+1')
    with pytest.raises(ConflictError): await repair.repair('a',preview['revision'],preview['confirmed_snapshot'])
    preview=repair.preview(); args=('a',preview['revision'],preview['confirmed_snapshot'])
    await repair.repair(*args)
    with pytest.raises(ConflictError): await repair.repair('a',preview['revision'],{'id':'bad','at':t.wall})

@pytest.mark.asyncio
async def test_quarantine_never_spends_expires_or_compensates(tmp_path):
    from server.app.availability import AvailabilityService
    from tests.test_availability import healthy
    store,creds,repo,wall,before=funded(tmp_path)
    t=Time(wall[0]); clock=t.clock(); t.confirm(clock); store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy); await service.recover()
    await service.shutdown()
    anchor=store.get_metadata('clock_anchor'); original=operations(store)
    t.wall+=90*86400
    assert not await service.sample()
    repo.reconcile(creds.client_id,t.wall,timezone='UTC')
    assert not store.record_expiry(creds.client_id,t.wall)
    assert operations(store)==original and store.get_metadata('clock_anchor')==anchor
    t.confirm(clock); await service.sample()
    assert not operations(store,'compensation')

@pytest.mark.asyncio
async def test_host_timeout_invalidates_proof(tmp_path):
    from server.app.clock import ClockMonitor
    t=Time(); clock=t.clock(); t.confirm(clock)
    store=Store(tmp_path/'state.db','example.org',clock=clock)
    class Host:
        async def get(self,path): raise TimeoutError()
    await ClockMonitor(store,clock,Host()).sample()
    assert not clock.reliable and clock.confirmed_snapshot() is None
    assert clock.ambiguous and store.get_metadata("clock_ambiguous") is True

@pytest.mark.asyncio
async def test_repair_transaction_rollback_and_retry_after_restart(tmp_path,monkeypatch):
    import server.app.clock_repair as module
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    preview=repair.preview(); args=('a',preview['revision'],preview['confirmed_snapshot'])
    old=module.append_event
    def fail(*args,**kwargs): raise RuntimeError('crash before commit')
    monkeypatch.setattr(module,'append_event',fail)
    with pytest.raises(RuntimeError): await repair.repair(*args)
    assert repair.preview()['revision']==preview['revision'] and not clock.reliable
    monkeypatch.setattr(module,'append_event',old)
    result=await repair.repair(*args)
    reopened=Store(store.path,'example.org',clock=t.clock(store.get_metadata('clock_anchor')))
    assert await module.ClockRepair(reopened,reopened.clock).repair(*args)==result
    assert not reopened.clock.reliable

@pytest.mark.asyncio
async def test_holds_proof_and_correction_roundtrip(tmp_path):
    from tests.test_billing_backup import package,PASSWORD
    from server.app.backup import restore_state
    from server.app.subscription import first_period
    store,creds,repo,t,clock,repair=await poisoned(tmp_path/'source')
    p=repair.preview(); await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    target=tmp_path/'target'; restore_state(package(store),PASSWORD,target,'example.org','tunnel.example.org')
    copied=Store(target/'state.db','example.org',clock=t.clock(store.get_metadata('clock_anchor')))
    with copied.connection() as db: assert db.execute('PRAGMA user_version').fetchone()[0]==6
    assert copied.get_metadata('clock_hold:'+creds.client_id) is True
    assert copied.get_metadata('clock_proof')==store.get_metadata('clock_proof')
    assert not copied.clock.reliable
    period=first_period(t.wall-60,'UTC'); p=repair.preview()
    await repair.reconcile_period(creds.client_id,'b',p['revision'],period.start,period.end,'UTC','Сверка',p['clients'][0]['operation_ids'])
    target2=tmp_path/'target2'; restore_state(package(store),PASSWORD,target2,'example.org','tunnel.example.org')
    copied2=Store(target2/'state.db','example.org')
    assert operations(copied2,'period_correction')==operations(store,'period_correction')
    assert not copied2.get_metadata('clock_hold:'+creds.client_id,False)

@pytest.mark.asyncio
async def test_checkpoint_does_not_stale_preview_but_new_confirmation_does(tmp_path):
    from server.app.subscription import first_period
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    p=repair.preview(); await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    p=repair.preview(); t.advance(10); store.set_metadata('clock_anchor',clock.checkpoint())
    assert repair.preview()['revision']==p['revision']
    t.wall+=100; clock.now(); t.confirm(clock)
    period=first_period(t.wall-60,'UTC')
    with pytest.raises(ConflictError):
        await repair.reconcile_period(creds.client_id,'b',p['revision'],period.start,period.end,'UTC','Сверка',p['clients'][0]['operation_ids'])


@pytest.mark.asyncio
async def test_protected_clock_http_and_legacy_client_wire(tmp_path):
    from aiohttp import encode_basic_auth
    from aiohttp.test_utils import TestClient,TestServer
    from server.app.identity import Authority
    from server.app.web import make_ingress_app,make_public_app
    from shared.billing_status import validate_billing
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    async def disconnect(cid): pass
    options={'server_url':'https://tunnel.example.org','admin_user_ids':['admin'],'ingress_ips':['127.0.0.1']}
    async with TestClient(TestServer(make_ingress_app(store,authority,options,disconnect))) as http:
        assert (await http.get('/api/clock/preview')).status==403
        headers={'X-Remote-User-Id':'admin'}
        response=await http.get('/api/clock/preview',headers=headers)
        assert response.status==200
        p=await response.json()
        assert p['repair_allowed'] is True
        payload={'command_id':'http','revision':p['revision'],'confirmed_snapshot':p['confirmed_snapshot']}
        assert (await http.post('/api/clock/repair',headers=headers,json=payload)).status==403
        state=await(await http.get('/api/state',headers=headers)).json(); headers['X-CSRF-Token']=state['csrf']
        assert (await http.post('/api/clock/repair',headers=headers,json={'command_id':'missing'})).status==400
        assert (await http.post('/api/clock/repair',headers=headers,json={**payload,'revision':'0'*64})).status==409
        assert (await http.post('/api/clock/repair',headers=headers,json=payload)).status==200
        from server.app.subscription import first_period
        p=await(await http.get('/api/clock/preview',headers=headers)).json()
        assert p['repair_allowed'] is False
        assert (await http.post('/api/clock/repair',headers=headers,json=payload)).status==200
        period=first_period(t.wall-60,'UTC')
        proposed={'revision':p['revision'],'paid_from':period.start,'paid_until':period.end,'timezone':'UTC','reason':'Сверка','operation_ids':p['clients'][0]['operation_ids']}
        route='/api/clients/'+creds.client_id
        response=await http.post(route+'/period-preview',headers=headers,json=proposed)
        assert response.status==200 and (await response.json())['new_period']['anchor_day']==17
        assert (await http.post(route+'/period-preview',headers={'X-Remote-User-Id':'admin'},json=proposed)).status==403
        assert (await http.post(route+'/period-reconciliation',headers=headers,json=proposed)).status==400
        assert (await http.post(route+'/period-reconciliation',headers=headers,json={**proposed,'command_id':'stale','revision':'0'*64})).status==409
    async with TestClient(TestServer(make_public_app(store,authority,{'trusted_proxy_ips':['127.0.0.1']}))) as http:
        assert (await http.post('/api/clock/repair',headers={'X-Forwarded-Proto':'https'},json=payload)).status==404
        response=await http.post('/v1/client/status',headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(creds.client_id,creds.secret)},json={'capabilities':[]})
        assert response.status==200
        body=await response.json(); assert body['access_state']=='clock_error'
        validate_billing(body['billing'])
        assert body['billing']['pause_reason']=='clock_error' and body['billing']['funds_until'] is None
    assert len(operations(store,'purchase'))==1

@pytest.mark.asyncio
async def test_price_pause_start_and_reenrollment_cannot_release_hold(tmp_path):
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    p=repair.preview(); await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    for price in (0,30000): command(repo,creds.client_id,'set_price',price,t.wall)
    for action in ('pause','start'):
        snap=store.access_snapshot(creds.client_id,t.wall)
        store.apply_access(creds.client_id,action,action,snap['revision'],t.wall)
    snap=store.access_snapshot(creds.client_id,t.wall)
    invite=store.reissue(creds.client_id,int(t.wall),expected_revision=snap['revision'])
    store.redeem(invite.code,int(t.wall),binding=(creds.client_id,creds.secret))
    assert store.access_snapshot(creds.client_id,t.wall)['access_state']=='clock_error'
    assert len(operations(store,'purchase'))==1


@pytest.mark.asyncio
@pytest.mark.parametrize("initial", ["ready", "false", "null", "timeout"])
@pytest.mark.parametrize("ambiguous", [False, True])
async def test_persisted_outage_after_fresh_boot_proof_keeps_compensation(tmp_path, initial, ambiguous):
    from server.app.clock import ClockMonitor
    from server.app.availability import AvailabilityService
    from tests.test_availability import healthy
    store,creds,repo,wall,before=funded(tmp_path)
    t=Time(wall[0]); clock=t.clock(); t.confirm(clock); store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy); await service.recover(); await service.shutdown()
    if ambiguous: store.set_metadata('clock_ambiguous',True)
    t.advance(37*3600)
    clock=t.clock(store.get_metadata('clock_anchor')); store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy)
    class Host:
        first=True
        async def get(self,path):
            if self.first and initial!='ready':
                self.first=False
                if initial=='timeout': raise TimeoutError()
                return {'dt_synchronized':False if initial=='false' else None}
            return {'dt_synchronized':True,'dt_utc':'same host wall clock'}
    monitor=ClockMonitor(store,clock,Host())
    if initial!='ready':
        baseline=store.get_metadata('service_last_healthy')
        await monitor.sample(); await service.recover()
        assert not clock.reliable and not operations(store,'compensation')
        assert store.get_metadata('service_last_healthy')==baseline
        t.advance(10)
    for n in range(3):
        await monitor.sample(); await service.recover()
        if n<2:
            assert not operations(store,'compensation'); t.advance(10)
    assert clock.reliable and len(operations(store,'compensation'))==(0 if ambiguous else 1)
    assert store.access_snapshot(creds.client_id,t.wall)['billing']['paid_until']==before['billing']['paid_until']+(0 if ambiguous else 2*86400)

@pytest.mark.asyncio
async def test_reconcile_atomic_replay_and_explicit_validation(tmp_path,monkeypatch):
    import server.app.clock_repair as module
    from server.app.subscription import first_period
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    p=repair.preview(); await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    period=first_period(t.wall-60,'UTC'); p=repair.preview()
    args=[creds.client_id,'b',p['revision'],period.start,period.end,'UTC','Сверка',p['clients'][0]['operation_ids']]
    for index,value in ((4,period.end+1),(5,'Missing/Zone'),(6,''),(7,['purchase:unknown'])):
        invalid=args.copy();invalid[index]=value
        with pytest.raises((ValueError,ConflictError)): await repair.reconcile_period(*invalid)
    original=module.append_event
    def fail(*args,**kwargs): raise RuntimeError('crash')
    monkeypatch.setattr(module,'append_event',fail)
    with pytest.raises(RuntimeError): await repair.reconcile_period(*args)
    assert repair.preview()['revision']==p['revision'] and not operations(store,'period_correction')
    monkeypatch.setattr(module,'append_event',original)
    result=await repair.reconcile_period(*args)
    assert await repair.reconcile_period(*args)==result
    assert len(operations(store,'period_correction'))==1
    assert operations(store,'period_correction')[0]['balance_before']==60000

@pytest.mark.parametrize('field,value',[('clock_proof',{'id':'a'*32,'at':True}),('clock_ambiguous',1),('clock_financial_anchor',-1),('clock_hold:'+'f'*32,True),('clock_command:'+'f'*64,{'request':'f'*64,'result':{'secret':'bad'}})])
@pytest.mark.asyncio
async def test_malformed_clock_metadata_never_replaces_destination(tmp_path,field,value):
    import json
    from tests.test_billing_backup import package,PASSWORD,modify
    from server.app.backup import restore_state
    store,creds,repo,t,clock,repair=await poisoned(tmp_path/'source')
    p=repair.preview(); await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    def corrupt(payload):
        payload['metadata']=[r for r in payload['metadata'] if r['name']!=field]+[{'name':field,'value':json.dumps(value)}]
    target=tmp_path/'target';Store(target/'state.db','example.org');before=(target/'state.db').read_bytes()
    with pytest.raises(ValueError): restore_state(modify(package(store),corrupt),PASSWORD,target,'example.org','tunnel.example.org')
    assert (target/'state.db').read_bytes()==before

@pytest.mark.asyncio
async def test_busy_administration_blocks_monitor_and_repair(tmp_path):
    import asyncio
    from server.app.clock import ClockMonitor
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    p=repair.preview()
    class Host:
        async def get(self,path): raise AssertionError('No Supervisor request while busy')
    async with store.administration.exclusive('restore'):
        assert not await ClockMonitor(store,clock,Host()).sample()
        with pytest.raises(ConflictError):
            await asyncio.create_task(repair.repair('a',p['revision'],p['confirmed_snapshot']))


def test_legacy_timed_mutation_waits_for_confirmed_time(tmp_path):
    store,creds,repo,wall,before=funded(tmp_path)
    with store.connection() as db: db.execute("UPDATE clients SET billing_mode='legacy',price_kopecks=0")
    store.clock=Time(wall[0]).clock()
    snap=store.access_snapshot(creds.client_id,wall[0])
    assert snap['access_state']=='clock_error'
    with pytest.raises(ConflictError):
        store.apply_access(creds.client_id,'set_duration','a',snap['revision'],wall[0],{'days':5},'UTC')


@pytest.mark.parametrize('start,end,timezone,anchor,next_end',[
    ('2027-01-31T10:00:00+00:00','2027-02-28T00:00:00+00:00','UTC',31,'2027-03-31T00:00:00+00:00'),
    ('2028-01-31T10:00:00+00:00','2028-02-29T00:00:00+00:00','UTC',31,'2028-03-31T00:00:00+00:00'),
    ('2026-03-15T10:00:00+01:00','2026-04-17T00:00:00+02:00','Europe/Berlin',17,'2026-05-17T00:00:00+02:00'),
])
def test_reconciled_calendar_supports_compensation_and_clamped_month(start,end,timezone,anchor,next_end):
    from datetime import datetime
    from server.app.clock_repair import reconciled_period
    from server.app.subscription import next_period
    period=reconciled_period(datetime.fromisoformat(start).timestamp(),datetime.fromisoformat(end).timestamp(),timezone)
    assert period.anchor_day==anchor
    assert next_period(period).end==datetime.fromisoformat(next_end).timestamp()

@pytest.mark.asyncio
@pytest.mark.parametrize("historical_start", [False, pytest.param(True, marks=pytest.mark.skipif(sys.platform=="win32", reason="Negative epoch datetime requires POSIX platform"))])
async def test_extended_period_preview_and_portable_correction(tmp_path, historical_start):
    from tests.test_billing_backup import package,PASSWORD
    from server.app.backup import restore_state
    from server.app.subscription import first_period
    store,creds,repo,t,clock,repair=await poisoned(tmp_path/'source')
    p=repair.preview(); await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    p=repair.preview(); first=first_period(t.wall-60,'UTC'); end=first.end+2*86400
    start=-86400 if historical_start else first.start
    proposed=repair.preview_period(creds.client_id,p['revision'],start,end,'UTC','Возврат двух подтверждённых дней',p['clients'][0]['operation_ids'])
    assert proposed['old_period']['paid_from']>t.wall
    assert proposed['new_period']['paid_until']==end and proposed['new_period']['anchor_day']==19
    args=(creds.client_id,'b',proposed['revision'],start,end,'UTC',proposed['reason'],proposed['operation_ids'])
    await repair.reconcile_period(*args)
    target=tmp_path/'target'; restore_state(package(store),PASSWORD,target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org')
    assert operations(restored,'period_correction')==operations(store,'period_correction')


@pytest.mark.asyncio
async def test_reconciliation_clears_financial_pause_without_clearing_manual_pause(tmp_path):
    from server.app.subscription import first_period
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    p=repair.preview(); await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    with store.connection() as db: db.execute('UPDATE clients SET billing_paused=1,paused=1')
    p=repair.preview();period=first_period(t.wall-60,'UTC')
    await repair.reconcile_period(creds.client_id,'b',p['revision'],period.start,period.end,'UTC','Сверка',p['clients'][0]['operation_ids'])
    with store.connection() as db:
        row=db.execute('SELECT paused,billing_paused FROM clients').fetchone()
    assert tuple(row)==(1,0)

@pytest.mark.asyncio
async def test_supervisor_host_info_allowlist_real_http(tmp_path,monkeypatch):
    import aiohttp
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from shared.supervisor_client import SupervisorClient
    async def info(request):
        assert request.headers['Authorization']=='Bearer isolated-test-token'
        return web.json_response({'result':'ok','data':{'dt_synchronized':True,'dt_utc':'2026-10-14T00:00:00Z'}})
    app=web.Application();app.router.add_get('/host/info',info)
    async with TestServer(app) as server:
        original=aiohttp.ClientSession
        class LocalSession:
            def __init__(self,**kwargs): self.session=original(**kwargs)
            async def __aenter__(self): return self
            async def __aexit__(self,*args): await self.session.close()
            def request(self,method,url,**kwargs):
                assert url=='http://supervisor/host/info'
                return self.session.request(method,server.make_url('/host/info'),**kwargs)
        monkeypatch.setattr(aiohttp,'ClientSession',LocalSession)
        client=SupervisorClient('isolated-test-token')
        assert (await client.get('/host/info'))['dt_synchronized'] is True
        for method,path in (('POST','/host/info'),('GET','/host/reboot'),('GET','/host')):
            with pytest.raises(ValueError): await client._request(method,path)



def test_schema_six_fences_old_readers_and_preserves_five_idempotently(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    with store.connection() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==6
        db.execute('PRAGMA user_version=5')
        before=list(db.iterdump())
    for _ in range(2):
        reopened=Store(store.path,'example.org',clock=lambda:now[0])
        with reopened.connection() as db:
            assert db.execute('PRAGMA user_version').fetchone()[0]==6
            assert list(db.iterdump())==before
    with store.connection() as db: db.execute('PRAGMA user_version=7')
    with pytest.raises(ValueError,match='newer version'): Store(store.path,'example.org')


@pytest.mark.parametrize('change',['unrelated_purchase','hold'])
@pytest.mark.asyncio
async def test_unrelated_financial_change_invalidates_period_preview(tmp_path,change):
    from server.app.subscription import first_period
    store,creds,repo,t,clock,repair=await poisoned(tmp_path)
    p=repair.preview();await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    other=store.redeem(store.issue('beta',int(t.wall)).code,int(t.wall))
    command(repo,other.client_id,'set_price',30000,t.wall)
    p=repair.preview();first=first_period(t.wall-60,'UTC')
    held=next(c for c in p['clients'] if c['client_id']==creds.client_id)
    if change=='unrelated_purchase': command(repo,other.client_id,'topup',30000,t.wall)
    else: store.set_metadata('clock_hold:'+other.client_id,True)
    with pytest.raises(ConflictError):
        await repair.reconcile_period(creds.client_id,'b',p['revision'],first.start,first.end,'UTC','Сверка',held['operation_ids'])
    assert store.get_metadata('clock_hold:'+creds.client_id) is True


@pytest.mark.asyncio
async def test_backup_receipt_cannot_claim_a_different_repair_result(tmp_path):
    import json
    from tests.test_billing_backup import package,PASSWORD,modify
    from server.app.backup import restore_state
    store,creds,repo,t,clock,repair=await poisoned(tmp_path/'source')
    p=repair.preview();await repair.repair('a',p['revision'],p['confirmed_snapshot'])
    def corrupt(payload):
        item=next(r for r in payload['metadata'] if r['name'].startswith('clock_command:'))
        receipt=json.loads(item['value']);receipt['result']['new_anchor']-=1;item['value']=json.dumps(receipt)
    with pytest.raises(ValueError):
        restore_state(modify(package(store),corrupt),PASSWORD,tmp_path/'target','example.org','tunnel.example.org')



def test_stable_subsecond_host_jitter_cannot_move_financial_time_backwards():
    t=Time();clock=t.clock();t.confirm(clock);t.advance(10)
    before=clock.now();t.wall-=0.5
    clock.observe_host({'dt_synchronized':True})
    assert clock.reliable and clock.now()>=before


def test_future_paid_period_never_falls_through_to_second_purchase(tmp_path):
    store,creds,repo,wall,before=funded(tmp_path)
    wall[0]-=0.5
    after=repo.reconcile(creds.client_id,wall[0],timezone='UTC')
    assert after['billing']['balance_kopecks']==before['billing']['balance_kopecks']
    assert store.get_metadata('clock_hold:'+creds.client_id) is True
    assert len(operations(store,'purchase'))==1



def test_purchase_then_subsecond_observation_keeps_balance_and_current_period(tmp_path):
    from tests.test_billing_store import connected
    store,creds,repo,wall=connected(tmp_path)
    t=Time(wall[0]);clock=t.clock();t.confirm(clock);store.clock=clock
    command(repo,creds.client_id,'set_price',30000,clock.now())
    t.advance(10);before=command(repo,creds.client_id,'topup',90000,clock.now())
    t.wall-=0.5;clock.observe_host({'dt_synchronized':True})
    after=repo.reconcile(creds.client_id,clock.now(),timezone='UTC')
    assert after['access_state']=='allowed'
    assert after['billing']['balance_kopecks']==60000 and after['billing']['paid_from']==before['billing']['paid_from']
    assert len(operations(store,'purchase'))==1

@pytest.mark.asyncio
async def test_future_period_without_marker_has_explicit_reconciliation_path(tmp_path):
    from server.app.clock_repair import ClockRepair
    from server.app.subscription import first_period
    store,creds,repo,wall,before=funded(tmp_path)
    t=Time(wall[0]-86400);clock=t.clock();t.confirm(clock);store.clock=clock
    repair=ClockRepair(store,clock);p=repair.preview()
    assert p['clients'][0]['hold'] and not store.get_metadata('clock_hold:'+creds.client_id,False)
    assert store.access_snapshot(creds.client_id,clock.now())['access_state']=='clock_error'
    period=first_period(t.wall-60,'UTC')
    await repair.reconcile_period(creds.client_id,'fix',p['revision'],period.start,period.end,'UTC','Сверка будущего периода',p['clients'][0]['operation_ids'])
    assert store.access_snapshot(creds.client_id,clock.now())['access_state']=='allowed'
    assert operations(store,'period_correction')[0]['balance_after']==60000


@pytest.mark.asyncio
async def test_reliable_jitter_repair_cannot_change_financial_state(tmp_path):
    from server.app.clock_repair import ClockRepair
    from server.app.availability import AvailabilityService
    from tests.test_availability import healthy
    from tests.test_billing_store import connected
    store,creds,repo,wall=connected(tmp_path)
    t=Time(wall[0]);clock=t.clock();t.confirm(clock);store.clock=clock
    command(repo,creds.client_id,'set_price',30000,clock.now())
    t.advance(10);command(repo,creds.client_id,'topup',90000,clock.now())
    service=AvailabilityService(store,clock,probe=healthy);await service.recover()
    used=clock.now();store.set_metadata('clock_anchor',clock.checkpoint())
    with store.connection() as db: before=list(db.iterdump())
    t.wall-=0.5;clock.observe_host({'dt_synchronized':True})
    repair=ClockRepair(store,clock);p=repair.preview()
    assert clock.reliable and p['confirmed_now']<p['old_anchor']
    with pytest.raises(ConflictError):
        await repair.repair('jitter',p['revision'],p['confirmed_snapshot'])
    assert p['repair_allowed'] is False
    assert clock.now()==used and not store.get_metadata('clock_hold:'+creds.client_id,False)
    assert store.access_snapshot(creds.client_id,clock.now())['access_state']=='allowed'
    with store.connection() as db: assert list(db.iterdump())==before
