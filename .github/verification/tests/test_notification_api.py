import asyncio
import pytest
from aiohttp.test_utils import TestClient, TestServer
from tests.test_notification_delivery import core, make_worker, current


async def apps(tmp_path,worker,role):
    options={'server_url':'https://tunnel.example.org','admin_user_ids':['admin'],'ingress_ips':['127.0.0.1']}
    if role=='server':
        from server.app.web import make_ingress_app
        from server.app.store import Store
        store=Store(tmp_path/'state.db','example.org',clock=lambda:1000000)
        async def disconnect(cid): pass
        async def admin(user): return user=='admin'
        return make_ingress_app(store,None,options,disconnect,admin_check=admin,notifications=worker),store
    from client.app.controller import Controller
    from client.app.web import make_app
    ctrl=Controller(tmp_path/'client',tmp_path/'configuration.yaml',object(),object())
    return make_app(ctrl,options,notifications=worker),ctrl


@pytest.mark.parametrize('role',['server','client'])
async def test_protected_settings_and_explicit_neutral_test(core,tmp_path,role):
    worker=make_worker(tmp_path,core,[]); app,owner=await apps(tmp_path,worker,role)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get('/api/notifications')).status==403
        headers={'X-Remote-User-Id':'admin'}
        result=await(await client.get('/api/notifications',headers=headers)).json()
        assert result['settings']['mobile_targets']==[] and not core.calls
        settings=result['settings']; settings['mobile_targets']=['notify.mobile_app_test']
        body=dict(settings=settings,revision=0,command_id='save-one')
        assert (await client.post('/api/notifications',headers=headers,json=body)).status==403
        headers['X-CSRF-Token']=result['csrf']
        assert (await client.post('/api/notifications',headers=headers,json=body)).status==200
        assert (await client.post('/api/notifications',headers=headers,json=body)).status==200
        body['command_id']='stale'
        assert (await client.post('/api/notifications',headers=headers,json=body)).status==409
        body['revision']=1; body['settings']['mobile_targets']=['notify.mobile_app_unknown']
        assert (await client.post('/api/notifications',headers=headers,json=body)).status==400
        assert not core.calls
        test=dict(revision=1,command_id='test-one')
        assert (await client.post('/api/notifications/test',headers=headers,json=test)).status==202
        await worker.tick(); assert len(core.mobile)==1
        assert core.mobile[0]['message']=='Проверка локальных уведомлений HA Tunnel.'
        assert (await client.post('/api/notifications/test',headers=headers,json=test)).status==202
        await worker.tick(); assert len(core.mobile)==1
    await worker.close()


async def test_server_guard_migration_and_notification_revision_independent(core,tmp_path):
    worker=make_worker(tmp_path,core,[current()]); app,store=await apps(tmp_path,worker,'server')
    async with TestClient(TestServer(app)) as client:
        h={'X-Remote-User-Id':'admin'}; result=await(await client.get('/api/notifications',headers=h)).json()
        h['X-CSRF-Token']=result['csrf']; body=dict(settings=result['settings'],revision=0,command_id='one')
        await worker.tick()
        assert (await client.post('/api/notifications',headers=h,json=body)).status==200
        body.update(revision=1,command_id='two'); store.migrating=True
        assert (await client.post('/api/notifications',headers=h,json=body)).status==409
        store.migrating=False
        entered=asyncio.Event(); release=asyncio.Event()
        async def hold():
            async with store.administration.exclusive('migration'): entered.set(); await release.wait()
        task=asyncio.create_task(hold()); await entered.wait()
        try: assert (await client.post('/api/notifications/test',headers=h,json={'revision':1,'command_id':'test'})).status==409
        finally: release.set(); await task
    await worker.close()


async def test_settings_survive_catalog_failure_and_other_role_namespace(core,tmp_path):
    from shared.notification_state import NotificationState
    worker=make_worker(tmp_path,core,[]); app,_=await apps(tmp_path,worker,'client')
    async with TestClient(TestServer(app)) as client:
        h={'X-Remote-User-Id':'admin'}; result=await(await client.get('/api/notifications',headers=h)).json(); h['X-CSRF-Token']=result['csrf']
        settings=result['settings']; settings['mobile_targets']=['notify.mobile_app_test']
        assert (await client.post('/api/notifications',headers=h,json=dict(settings=settings,revision=0,command_id='one'))).status==200
        core.catalog_status=503
        result=await(await client.get('/api/notifications',headers=h)).json()
        assert result['settings']['mobile_targets']==['notify.mobile_app_test']
        settings['warning_days']=9
        assert (await client.post('/api/notifications',headers=h,json=dict(settings=settings,revision=1,command_id='two'))).status==200
    other=NotificationState(tmp_path/'other.json','client')
    assert other.view()['settings']['mobile_targets']==[]
    assert other.identifier('server/account','financial')!=worker.state.identifier('server/account','financial')
    await worker.close()


def test_client_source_uses_server_receipt_time_and_ignores_secret_rotation(tmp_path):
    from client.app.controller import Controller
    from shared.notifications import client_snapshots
    from tests.test_notification_events import snapshot
    ctrl=Controller(tmp_path,tmp_path/'configuration.yaml',object(),object())
    ctrl.credentials=dict(client_id='a'*32,domain='alpha.example.org',server_url='https://tunnel.example.org',secret='synthetic')
    ctrl.server_access=snapshot(); ctrl.status_received=100; ctrl.billing_stale=False
    rows=client_snapshots(ctrl,monotonic=lambda:110)
    assert rows[0]['fresh'] and rows[0]['observed_now']==1000000
    first=rows[0]['binding_key']; ctrl.credentials['secret']='rotated'; ctrl.server_access['generation']=8
    assert client_snapshots(ctrl,monotonic=lambda:110)[0]['binding_key']==first
    assert not client_snapshots(ctrl,monotonic=lambda:146)[0]['fresh']
    ctrl.state='credentials_rejected'
    assert client_snapshots(ctrl,monotonic=lambda:146)[0]['rejected']


def test_server_source_reads_real_sqlite_without_reconciliation_writes(tmp_path):
    from tests.test_billing_store import funded
    from shared.notifications import server_snapshots
    store,c,repo,now,snap=funded(tmp_path)
    with store.connection() as db: before=list(db.iterdump())
    rows=server_snapshots(store)
    assert rows[0]['billing']['updated_at']==now[0]
    assert rows[0]['binding_key']==store.get_metadata('instance_id')+'/'+c.client_id
    assert rows[0]['reliable_time'] and rows[0]['fresh']
    with store.connection() as db: assert list(db.iterdump())==before


async def test_setup_view_serves_notification_form_and_configures_independently(core,tmp_path):
    from server.app.setup import SetupService,make_setup_app
    service=SetupService(tmp_path,object()); worker=make_worker(tmp_path,core,[])
    async def admin(user): return user=='admin'
    app=make_setup_app(service,admin,ingress_ips=['127.0.0.1'],notifications=worker)
    async with TestClient(TestServer(app)) as client:
        h={'X-Remote-User-Id':'admin'}
        assert (await client.get('/notification_settings.js',headers=h)).status==200
        page=await(await client.get('/',headers=h)).text()
        assert 'notification-settings' in page
        result=await(await client.get('/api/notifications',headers=h)).json(); h['X-CSRF-Token']=result['csrf']
        assert (await client.post('/api/notifications',headers=h,json=dict(settings=result['settings'],revision=0,command_id='save'))).status==200
        assert service.options is None or not service.options
    await worker.close()


async def test_server_status_contact_counts_without_frp_or_ha_sample(core,tmp_path):
    from server.app.web import make_public_app
    from server.app.store import Store
    from shared.notifications import server_snapshots
    from aiohttp import encode_basic_auth
    store=Store(tmp_path/'state.db','example.org',clock=lambda:1000000)
    c=store.redeem(store.issue('alpha',1000000).code,1000000)
    store.notification_contacts={f'deleted-{i}':1 for i in range(4096)}
    app=make_public_app(store,None,{'trusted_proxy_ips':['127.0.0.1']})
    async with TestClient(TestServer(app)) as client:
        response=await client.post('/v1/client/status',headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(c.client_id,c.secret)},json={'capabilities':['access-v1']})
        assert response.status==200
    assert server_snapshots(store)[0]['contact']
    assert set(store.notification_contacts)=={c.client_id}
    receipt=store.notification_contacts[c.client_id]
    worker=make_worker(tmp_path,core,[])
    settings=worker.state.view()['settings']; settings['connection']=True
    worker.state.configure(settings,0,'enable')
    worker.snapshots=lambda:server_snapshots(store)
    worker.monotonic=lambda:receipt+599
    try:
        await worker.tick(); assert not core.cards
        worker.monotonic=lambda:receipt+600
        await worker.tick(); assert len(core.cards)==1
        assert '10 минут' in next(iter(core.cards.values()))['message']
    finally: await worker.close()


async def test_frp_contact_only_current_authenticated_owner(tmp_path,monkeypatch):
    from server.app.store import Store
    from server.app.identity import Authority
    from server.app.web import make_plugin_app
    store=Store(tmp_path/'state.db','example.org',clock=lambda:1000000)
    c=store.redeem(store.issue('alpha',1000000).code,1000000)
    authority=Authority(tmp_path/'key','http://127.0.0.1:19000')
    jwt=authority.issue(c.client_id)
    async with TestClient(TestServer(make_plugin_app(store,authority))) as client:
        async def call(op,content):
            return await(await client.post('/handler?version=0.1.0&op='+op,json={'version':'0.1.0','op':op,'content':content})).json()
        login=await call('Login',{'user':c.client_id,'privilege_key':jwt,'metas':{'ha_tunnel_process':'a'*32}})
        assert not login['reject']
        assert c.client_id in store.notification_contacts
        user={k:login['content'][k] for k in ('user','run_id','metas')}
        store.notification_contacts[c.client_id]=1
        assert not (await call('Ping',{'user':user,'privilege_key':jwt}))['reject']
        receipt=store.notification_contacts[c.client_id]; assert receipt>1
        assert (await call('Login',{'user':c.client_id,'privilege_key':jwt,'metas':{'ha_tunnel_process':'b'*32}}))['reject']
        stale={**user,'run_id':'previous-owner'}
        assert (await call('Ping',{'user':stale,'privilege_key':jwt}))['reject']
        await call('CloseProxy',{'user':stale,'proxy_name':c.client_id+'.ha'})
        assert (await call('Ping',{'user':user,'privilege_key':'invalid'}))['reject']
        assert store.notification_contacts[c.client_id]==receipt
        store.notification_contacts={f'deleted-{i}':1 for i in range(4096)}
        def unavailable(): raise OSError('synthetic optional observation failure')
        monkeypatch.setattr(store,'list_clients',unavailable)
        assert not (await call('Ping',{'user':user,'privilege_key':jwt}))['reject']
        assert len(store.notification_contacts)==4096


async def test_client_restart_and_secret_rotation_keep_financial_episode(core,tmp_path):
    from client.app.controller import Controller
    from shared.notifications import client_snapshots
    from tests.test_notification_events import snapshot
    ctrl=Controller(tmp_path/'client',tmp_path/'configuration.yaml',object(),object())
    ctrl.credentials=dict(client_id='a'*32,domain='alpha.example.org',server_url='https://tunnel.example.org',secret='first')
    ctrl.server_access=snapshot(); ctrl.status_received=100; ctrl.billing_stale=False
    worker=make_worker(tmp_path,core,[]); worker.snapshots=lambda:client_snapshots(ctrl,monotonic=lambda:110)
    try:
        await worker.tick(); ident=next(iter(core.cards)); version=worker.state.records[ident]['version']
        ctrl.credentials['secret']='rotated'; ctrl.server_access=None; ctrl.status_received=None; ctrl.billing_stale=True
        await worker.close(); worker=make_worker(tmp_path,core,[]); worker.snapshots=lambda:client_snapshots(ctrl,monotonic=lambda:110)
        await worker.tick(); assert ident in worker.state.records and worker.state.records[ident]['version']==version
        ctrl.server_access=snapshot(); ctrl.status_received=100; ctrl.billing_stale=False
        await worker.tick(); assert worker.state.records[ident]['version']==version
    finally: await worker.close()


async def test_client_contact_requires_authenticated_status_not_legacy_health(tmp_path):
    import time
    from client.app.controller import Controller
    from shared.notifications import client_snapshots
    from tests.test_notification_events import snapshot
    ctrl=Controller(tmp_path,tmp_path/'configuration.yaml',object(),object())
    ctrl.credentials=dict(client_id='a'*32,domain='alpha.example.org',server_url='https://tunnel.example.org',secret='synthetic')
    class Status:
        value=None
        async def fetch(self,*args): return self.value
    ctrl.status_client=Status(); ctrl.status_origin=ctrl.credentials['server_url']
    await ctrl.poll_access()
    assert not client_snapshots(ctrl)[0]['contact']
    ctrl.status_client.value=snapshot(); await ctrl.poll_access()
    assert client_snapshots(ctrl)[0]['contact']


async def test_production_notification_worker_reads_snapshot_without_administration(core,tmp_path,monkeypatch):
    from server.app.store import Store
    from shared.notifications import server_snapshots
    store=Store(tmp_path/'state.db','example.org',clock=lambda:1000000)
    c=store.redeem(store.issue('alpha',1000000).code,1000000)
    from server.app.main import notification_worker
    monkeypatch.setenv('SUPERVISOR_TOKEN','synthetic-token')
    worker=notification_worker(tmp_path,store.administration,store)
    # A real paid account produces a local card without occupying Administration.
    from server.app.billing import BillingRepository
    BillingRepository(store).command(c.client_id,'set_price','price',0,value_kopecks=100,now=1000000,timezone='UTC')
    try:
        await worker.tick()
        assert core.cards and not store.administration.busy
    finally: await worker.close()


async def test_test_history_not_replayed_to_new_target_or_after_core_restart(core,tmp_path):
    worker=make_worker(tmp_path,core,[])
    settings=worker.state.view()['settings']; settings['mobile_targets']=['notify.mobile_app_test']
    worker.state.configure(settings,0,'first'); worker.state.request_test(1,'test')
    try:
        await worker.tick(); assert len(core.mobile)==1
        core.cards.clear(); await worker.close()
        worker=make_worker(tmp_path,core,[])
        settings['mobile_targets']=['notify.mobile_app_other']; worker.state.configure(settings,1,'second')
        core.catalog=[{'domain':'notify','services':{'mobile_app_other':{}}}]
        await worker.tick()
        assert len(core.mobile)==1 and not core.cards
    finally: await worker.close()


async def test_settings_get_runs_between_slow_delivery_operations(core,tmp_path):
    rows=[current(),{**current(),'binding_key':'second','domain':'second.example.org'}]
    worker=make_worker(tmp_path,core,rows); app,_=await apps(tmp_path,worker,'client')
    entered=[asyncio.Event(),asyncio.Event()]; release=[asyncio.Event(),asyncio.Event()]; calls=0
    async def slow_create():
        nonlocal calls
        index=calls; calls+=1
        entered[index].set(); await release[index].wait()
    core.before_create=slow_create
    async with TestClient(TestServer(app)) as client:
        tick=asyncio.create_task(worker.tick())
        await asyncio.wait_for(entered[0].wait(),1)
        reading=asyncio.create_task(client.get('/api/notifications',headers={'X-Remote-User-Id':'admin'}))
        await asyncio.sleep(.03); release[0].set()
        try:
            await asyncio.wait_for(entered[1].wait(),1)
            response=await asyncio.wait_for(reading,.3)
            assert response.status==200
            assert (await response.json())['revision']==0
        finally:
            release[1].set(); await tick
            reading.cancel(); await asyncio.gather(reading,return_exceptions=True)
            await worker.close()


async def test_concurrent_settings_change_drops_remaining_obsolete_sends(core,tmp_path):
    rows=[current(),{**current(),'binding_key':'second','domain':'second.example.org'}]
    worker=make_worker(tmp_path,core,rows); app,_=await apps(tmp_path,worker,'client')
    entered=asyncio.Event(); release=asyncio.Event(); calls=0
    async def slow_create():
        nonlocal calls
        calls+=1
        if calls==1: entered.set(); await release.wait()
    core.before_create=slow_create
    async with TestClient(TestServer(app)) as client:
        headers={'X-Remote-User-Id':'admin'}
        view=await(await client.get('/api/notifications',headers=headers)).json()
        headers['X-CSRF-Token']=view['csrf']; view['settings']['enabled']=False
        tick=asyncio.create_task(worker.tick()); await asyncio.wait_for(entered.wait(),1)
        saving=asyncio.create_task(client.post('/api/notifications',headers=headers,json={
            'settings':view['settings'],'revision':0,'command_id':'disable'}))
        await asyncio.sleep(.03); release.set()
        try:
            assert (await asyncio.wait_for(saving,1)).status==200
            await tick
            assert calls==1
            second=worker.state.records[worker.state.identifier('second','financial')]
            assert second['desired'] is None and second['created_at'] is None and second['mobile']=={}
        finally:
            release.set(); await asyncio.gather(tick,saving,return_exceptions=True); await worker.close()


async def test_blocked_core_does_not_block_status_clock_or_paid_reconciliation(core,tmp_path,monkeypatch):
    from aiohttp import encode_basic_auth
    from tests.test_billing_store import funded,operations
    from server.app.main import notification_worker
    from server.app.web import make_public_app
    from server.app.clock import SafeClock,ClockMonitor
    from server.app.access import AccessService
    from server.app.relay import ClientRelay
    store,c,repo,now,snap=funded(tmp_path)
    now[0]=snap['billing']['paid_until']+1; mono=[0]
    clock=SafeClock(wall=lambda:now[0],monotonic=lambda:mono[0])
    for _ in range(3):
        clock.observe_host({'dt_synchronized':True}); now[0]+=10; mono[0]+=10
    assert clock.reliable
    store.clock=clock
    class Supervisor:
        calls=0
        async def get(self,path):
            assert path=='/host/info'; self.calls+=1; return {'dt_synchronized':True}
    supervisor=Supervisor(); monitor=ClockMonitor(store,clock,supervisor)
    relay=ClientRelay(store,clock); access=AccessService(store,relay,clock)
    monkeypatch.setenv('SUPERVISOR_TOKEN','synthetic-token')
    worker=notification_worker(tmp_path,store.administration,store)
    worker.state.request_test(0,'explicit')
    entered=asyncio.Event(); release=asyncio.Event()
    async def blocked(): entered.set(); await release.wait()
    core.before_create=blocked
    await worker.start()
    try:
        await asyncio.wait_for(entered.wait(),1)
        async with TestClient(TestServer(make_public_app(store,None,{'trusted_proxy_ips':['127.0.0.1']}))) as client:
            response=await client.post('/v1/client/status',headers={'X-Forwarded-Proto':'https',
                'Authorization':encode_basic_auth(c.client_id,c.secret)},json={'capabilities':['access-v1']})
            assert response.status==200
        assert await monitor.sample() and supervisor.calls==1
        await access.expire_once()
        assert len(operations(store,'purchase'))==2
        assert store.access_snapshot(c.client_id,now[0])['access_state']=='allowed'
        assert not store.administration.busy
        # Restore's existing exclusive scope can stop this pending own delivery
        # before a financial state swap; it never needs to await Core release.
        async with store.administration.exclusive('restore'):
            await asyncio.wait_for(worker.close(),1)
            store.migrating=True
        assert worker.task is None and worker.observer is None
    finally: release.set(); await worker.close(); await relay.close()


@pytest.mark.parametrize('role',['server','client'])
@pytest.mark.parametrize('funding',['renewable','unpaid','legacy'])
async def test_real_period_boundary_never_invents_funded_stop_or_recovery(core,tmp_path,role,funding):
    from tests.test_billing_store import funded,connected,command,ZONE
    from shared.notifications import server_snapshots,client_snapshots
    from client.app.controller import Controller
    if funding=='renewable': store,c,repo,now,snap=funded(tmp_path)
    else:
        store,c,repo,now=connected(tmp_path)
        if funding=='unpaid':
            command(repo,c.client_id,'set_price',30000,now[0])
            snap=command(repo,c.client_id,'topup',30000,now[0])
        else: snap=store.apply_access(c.client_id,'set_duration','duration',0,now[0],{'minutes':20})
    now[0]=(snap['deadline'] if funding=='legacy' else snap['billing']['paid_until'])+1
    ctrl=Controller(tmp_path/'client',tmp_path/'configuration.yaml',object(),object())
    ctrl.credentials=dict(client_id=c.client_id,domain=c.domain,server_url='https://tunnel.example.org',secret=c.secret)
    def sources():
        rows=server_snapshots(store)
        if role=='server': return rows
        ctrl.server_access=rows[0]; ctrl.status_received=100; ctrl.billing_stale=False
        return client_snapshots(ctrl,monotonic=lambda:110)
    worker=make_worker(tmp_path,core,[],role=role); worker.snapshots=sources
    settings=worker.state.view()['settings']; settings['mobile_targets']=['notify.mobile_app_test']
    worker.state.configure(settings,0,'phone')
    try:
        raw=sources()[0]; assert raw['access_state']=='expired'
        with store.connection() as db: before=list(db.iterdump())
        await worker.tick()
        with store.connection() as db: assert list(db.iterdump())==before
        if funding=='renewable':
            assert raw['billing']['balance_kopecks']>=raw['billing']['price_kopecks']
            assert not core.cards and not core.mobile
            assert all(not r['context'].get('stopped') for r in worker.state.records.values())
            repo.reconcile(c.client_id,now[0],timezone=ZONE)
            assert sources()[0]['access_state']=='allowed'
            await worker.tick()
            assert not core.cards and not core.mobile
            assert all(not r['context'].get('recovered') for r in worker.state.records.values())
        else:
            assert len(core.cards)==len(core.mobile)==1
            assert any(r['desired'] and r['desired']['kind']=='access_stopped' for r in worker.state.records.values())
    finally: await worker.close()
