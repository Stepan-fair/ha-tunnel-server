import asyncio
import json
import pytest
from server.app.store import Store, ConflictError
from server.app.access import AccessService
from server.app.relay import ClientRelay
from tests.test_billing_store import funded, operations


def connected(tmp_path):
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    c=store.redeem(store.issue('alpha',2000).code,2000)
    return store,c


def test_stale_reissue_cannot_replace_new_binding(tmp_path):
    store,c=connected(tmp_path)
    code=store.reissue(c.client_id,2000,expected_revision=0).code
    newer=store.redeem(code,2000,binding=(c.client_id,c.secret))
    with pytest.raises(ConflictError): store.reissue(c.client_id,2000,expected_revision=0)
    assert store.authenticate(c.client_id,newer.secret)


def test_transfer_requires_explicit_replacement_and_replay_binds_invitation(tmp_path):
    store,c=connected(tmp_path)
    first=store.reissue(c.client_id,2000,transfer=True,expected_revision=0,confirm_domain=c.domain,command_id='first')
    rev=store.access_snapshot(c.client_id,2000)['revision']
    assert rev==1
    assert store.reissue(c.client_id,2000,transfer=True,expected_revision=0,confirm_domain=c.domain,command_id='first')==first
    with pytest.raises(ConflictError):
        store.reissue(c.client_id,2000,transfer=True,expected_revision=rev,confirm_domain=c.domain,command_id='second')
    second=store.reissue(c.client_id,2000,transfer=True,expected_revision=rev,confirm_domain=c.domain,command_id='second',replace_pending=True)
    with pytest.raises(ConflictError):
        store.reissue(c.client_id,2000,transfer=True,expected_revision=0,confirm_domain=c.domain,command_id='first')
    with pytest.raises(ValueError): store.redeem(first.code,2000)
    assert store.show_code(c.client_id,2000).code==second.code
    with store.connection() as db:
        assert first.code not in str([tuple(r) for r in db.execute('SELECT * FROM invitation_commands')])


@pytest.mark.parametrize('balance',[-1,1])
def test_delete_preserves_nonzero_balance(tmp_path,balance):
    store,c=connected(tmp_path)
    with store.connection() as db: db.execute('UPDATE clients SET balance_kopecks=? WHERE id=?',(balance,c.client_id))
    store.revoke(c.client_id)
    with pytest.raises(ConflictError): store.delete_revoked(c.client_id,1)
    assert store.access_snapshot(c.client_id,2000)['billing']['balance_kopecks']==balance


@pytest.mark.parametrize('future',[False,True])
def test_delete_preserves_paid_period_after_price_changed_to_zero(tmp_path,future):
    store,c,repo,now,snap=funded(tmp_path)
    if future: now[0]-=86400
    repo.command(c.client_id,'set_price','free',snap['revision'],value_kopecks=0,now=now[0],timezone='UTC')
    with store.connection() as db: db.execute('UPDATE clients SET balance_kopecks=0 WHERE id=?',(c.client_id,))
    store.revoke(c.client_id)
    rev=store.access_snapshot(c.client_id,now[0])['revision']
    before=operations(store)
    with pytest.raises(ConflictError): store.delete_revoked(c.client_id,rev)
    assert operations(store)==before


@pytest.mark.parametrize('reason',['migration','clock'])
def test_delete_requires_reliable_unblocked_state(tmp_path,reason):
    store,c=connected(tmp_path); store.revoke(c.client_id)
    if reason=='migration': store.migrating=True
    else:
        class Clock:
            reliable=False
            def now(self): return 2000
        store.clock=Clock()
    with pytest.raises(ConflictError): store.delete_revoked(c.client_id,1)
    assert store.list_clients()


async def test_guard_is_reentrant_only_for_owner_and_rechecks_after_relay_wait(tmp_path):
    store,c=connected(tmp_path)
    relay=ClientRelay(store,store.clock); access=AccessService(store,relay,store.clock)
    async with relay.locks[c.client_id]:
        pending=asyncio.create_task(access.command(c.client_id,'revoke','r',0))
        await asyncio.sleep(0)
        async with store.administration.exclusive('restore'):
            async with store.administration.exclusive('setup'):
                store.administration.ensure_mutation_allowed()
            async def other():
                with pytest.raises(ConflictError): store.issue('other',2000)
            await asyncio.create_task(other())
            relay.locks[c.client_id].release()
            try:
                with pytest.raises(ConflictError): await pending
            finally: await relay.locks[c.client_id].acquire()
    assert store.authenticate(c.client_id,c.secret)


async def test_setup_preserves_verified_actor_and_validates_candidate_before_write(tmp_path):
    from tests.test_server_setup import Supervisor,draft
    from server.app.setup import SetupService
    from server.app.journal import Actor,current_actor
    supervisor=Supervisor(); supervisor.options=draft()
    service=SetupService(tmp_path,supervisor)
    async def verify(uid): return uid in ('admin','other')
    async def reject(options): raise ValueError('NPM candidate rejected')
    service.admin_validator=verify; service.candidate_validator=reject
    token=current_actor.set(Actor('web','admin'))
    try:
        with pytest.raises(ValueError):
            await service.save({**draft(),'admin_user_ids':['other']},service.revision(draft()))
        with pytest.raises(ValueError,match='candidate'):
            await service.save(draft(),service.revision(draft()))
        assert supervisor.options==draft() and supervisor.writes==[]
        assert not (tmp_path/'setup.draft.json').exists()
    finally: current_actor.reset(token)

async def test_ingress_stale_revoke_and_reissue_never_target_new_binding(tmp_path):
    from aiohttp.test_utils import TestClient,TestServer
    from server.app.web import make_ingress_app
    from server.app.identity import Authority
    store,c=connected(tmp_path)
    relay=ClientRelay(store,store.clock);access=AccessService(store,relay,store.clock)
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    async with TestClient(TestServer(make_ingress_app(store,Authority(tmp_path/'identity.key','http://localhost'),options,relay.disconnect,access=access))) as client:
        headers={'X-Remote-User-Id':'owner'}
        headers['X-CSRF-Token']=(await(await client.get('/api/state',headers=headers)).json())['csrf']
        code=store.reissue(c.client_id,2000,transfer=True,expected_revision=0,confirm_domain=c.domain).code
        newer=store.redeem(code,2000)
        for endpoint in ('revoke','invitation/reissue'):
            r=await client.post('/api/clients/'+c.client_id+'/'+endpoint,headers=headers,json={'revision':0,'command_id':'stale-'+endpoint})
            assert r.status==409
            assert store.authenticate(c.client_id,newer.secret)
            assert (await client.post('/api/clients/'+c.client_id+'/'+endpoint,headers=headers,json={})).status in (400,409)


async def test_ingress_confirmation_bound_to_preview_and_blocks_mutation_during_restore(tmp_path):
    from aiohttp.test_utils import TestClient,TestServer
    from server.app.web import make_ingress_app
    from server.app.identity import Authority
    from tests.test_billing_backup import package,PASSWORD
    import base64
    source=Store(tmp_path/'source/state.db','example.org');blob=package(source)
    store=Store(tmp_path/'target/state.db','example.org')
    entered=asyncio.Event();release=asyncio.Event()
    async def restore(blob,password,**kwargs): entered.set();await release.wait()
    async def disconnect(cid): pass
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    app=make_ingress_app(store,Authority(tmp_path/'target/identity.key','http://localhost'),options,disconnect,backup_restore=restore)
    async with TestClient(TestServer(app)) as client:
        headers={'X-Remote-User-Id':'owner'};headers['X-CSRF-Token']=(await(await client.get('/api/state',headers=headers)).json())['csrf']
        body={'backup':base64.b64encode(blob).decode(),'password':PASSWORD}
        r=await client.post('/api/backup/preview',headers=headers,json=body)
        assert r.status==200
        preview=await r.json()
        assert (await client.post('/api/backup/restore',headers=headers,json=body)).status==400
        body.update(digest=preview['digest'],revision=preview['revision'],confirm_unknown_date=False)
        task=asyncio.create_task(client.post('/api/backup/restore',headers=headers,json=body))
        await asyncio.wait_for(entered.wait(),2)
        try:
            assert (await client.post('/api/clients',headers=headers,json={'name':'racing'})).status==409
            assert not store.list_clients()
        finally: release.set()
        assert (await task).status==200

async def test_timer_waiting_for_client_lock_does_not_fail_or_mutate_during_admin(tmp_path):
    store,c=connected(tmp_path)
    relay=ClientRelay(store,store.clock);access=AccessService(store,relay,store.clock)
    async with relay.locks[c.client_id]:
        pending=asyncio.create_task(access.expire_once());await asyncio.sleep(0)
        async with store.administration.exclusive('restore'):
            relay.locks[c.client_id].release()
            try: await pending
            finally: await relay.locks[c.client_id].acquire()
    assert store.authenticate(c.client_id,c.secret)


async def test_availability_does_not_commit_after_probe_resumes_in_admin_operation(tmp_path):
    from server.app.availability import AvailabilityService
    from tests.test_availability import Clock,healthy
    store,c,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]);service=AvailabilityService(store,clock,probe=healthy)
    await service.recover();await service.shutdown();clock.value+=37*3600
    entered=asyncio.Event();release=asyncio.Event()
    async def probe(): entered.set();await release.wait();return await healthy()
    service.probe=probe
    pending=asyncio.create_task(service.sample());await entered.wait()
    before=operations(store)
    async with store.administration.exclusive('restore'):
        release.set();await pending
        assert operations(store)==before
    await service.sample()
    assert len(operations(store,'compensation'))==1


async def test_setup_checks_persisted_incomplete_migration_before_writing(tmp_path):
    from tests.test_server_setup import Supervisor,draft
    from server.app.setup import SetupService
    store=Store(tmp_path/'state/state.db','example.org')
    store.set_metadata('domain_migration',{'phase':'prepared'})
    supervisor=Supervisor();supervisor.options=draft()
    service=SetupService(tmp_path,supervisor)
    with pytest.raises(ValueError): await service.save(draft(),service.revision(draft()))
    assert supervisor.writes==[]

@pytest.mark.parametrize('new_user',[
    {'id':'other','is_active':False,'group_ids':['system-admin']},
    {'id':'other','is_active':True,'group_ids':['system-users']},
])
async def test_setup_rejects_added_admin_using_real_core_protocol(tmp_path,monkeypatch,new_user):
    import aiohttp
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from server.app.setup import SetupService
    from server.app.journal import Actor,current_actor
    from tests.test_server_setup import Supervisor,draft
    async def handler(request):
        ws=web.WebSocketResponse();await ws.prepare(request)
        await ws.send_json({'type':'auth_required'})
        assert await ws.receive_json()=={'type':'auth','access_token':'synthetic-token'}
        await ws.send_json({'type':'auth_ok'})
        assert await ws.receive_json()=={'id':1,'type':'config/auth/list'}
        await ws.send_json({'id':1,'success':True,'result':[{'id':'admin','is_active':True,'is_owner':True},new_user]})
        await ws.close();return ws
    app=web.Application();app.router.add_get('/core/websocket',handler)
    async with TestServer(app) as server:
        original=aiohttp.ClientSession.ws_connect
        def connect(session,url,**kwargs):
            assert url=='http://supervisor/core/websocket'
            return original(session,str(server.make_url('/core/websocket')),**kwargs)
        monkeypatch.setattr(aiohttp.ClientSession,'ws_connect',connect)
        monkeypatch.setenv('SUPERVISOR_TOKEN','synthetic-token')
        supervisor=Supervisor();supervisor.options=draft();service=SetupService(tmp_path,supervisor)
        token=current_actor.set(Actor('web','admin'))
        try:
            with pytest.raises(ValueError):
                await service.save({**draft(),'admin_user_ids':['admin','other']},service.revision(draft()))
            assert supervisor.writes==[]
        finally: current_actor.reset(token)


async def test_setup_guard_covers_awaited_dependency_and_releases_on_failure(tmp_path):
    from server.app.setup import SetupService
    from tests.test_server_setup import Supervisor,draft
    store,c=connected(tmp_path);supervisor=Supervisor();supervisor.options=draft()
    entered=asyncio.Event();release=asyncio.Event()
    async def validator(options):
        entered.set();await release.wait();raise ValueError('candidate unavailable')
    service=SetupService(tmp_path,supervisor,administration=store.administration,candidate_validator=validator)
    pending=asyncio.create_task(service.save(draft(),service.revision(draft())))
    await entered.wait()
    try:
        with pytest.raises(ConflictError): store.reissue(c.client_id,2000)
        with pytest.raises(ConflictError):
            async with store.administration.exclusive('migration'): pass
    finally: release.set()
    with pytest.raises(ValueError): await pending
    assert not store.administration.busy and supervisor.writes==[]
    assert store.authenticate(c.client_id,c.secret)

async def test_runtime_restart_cannot_cross_restore_guard(tmp_path):
    import sys
    from server.app.runtime import ServerRuntime
    store,c=connected(tmp_path)
    helper=tmp_path/'child.py';helper.write_text('import time\ntime.sleep(60)\n')
    runtime=ServerRuntime(sys.executable,tmp_path/'runtime.json',store)
    runtime.prefix=[str(helper)];runtime.verify=False
    await runtime.start({})
    try:
        before=runtime.process.pid
        async with store.administration.exclusive('restore'):
            task=asyncio.create_task(runtime.restart())
            with pytest.raises(ConflictError): await task
            assert runtime.process.pid==before and runtime.status()['running']
    finally: await runtime.stop()

async def test_http_replay_never_revokes_replacement_or_returns_a_different_code(tmp_path):
    from aiohttp.test_utils import TestClient,TestServer
    from server.app.web import make_ingress_app
    from server.app.identity import Authority
    from shared.protocol import Invitation
    store,c=connected(tmp_path);relay=ClientRelay(store,store.clock)
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    app=make_ingress_app(store,Authority(tmp_path/'identity.key','http://localhost'),options,relay.disconnect,access=AccessService(store,relay,store.clock))
    async with TestClient(TestServer(app)) as client:
        headers={'X-Remote-User-Id':'owner'};headers['X-CSRF-Token']=(await(await client.get('/api/state',headers=headers)).json())['csrf']
        path='/api/clients/'+c.client_id
        for endpoint in ('revoke','invitation/reissue','invitation/transfer'):
            for body in ({'revision':0},{'command_id':'missing'}):
                if endpoint.endswith('transfer'): body['confirm_domain']=c.domain
                assert (await client.post(path+'/'+endpoint,headers=headers,json=body)).status==400
        revoke={'revision':0,'command_id':'first-revoke'}
        assert (await client.post(path+'/revoke',headers=headers,json=revoke)).status==200
        transfer={'revision':1,'command_id':'move','confirm_domain':c.domain}
        first=await(await client.post(path+'/invitation/transfer',headers=headers,json=transfer)).json()
        again=await(await client.post(path+'/invitation/transfer',headers=headers,json=transfer)).json()
        assert first['invitation']==again['invitation']
        newer=store.redeem(Invitation.parse(first['invitation']).code,2000)
        assert (await client.post(path+'/revoke',headers=headers,json=revoke)).status==200
        assert store.authenticate(c.client_id,newer.secret)
        assert (await client.post(path+'/invitation/transfer',headers=headers,json=transfer)).status==409
        body={'revision':store.access_snapshot(c.client_id,2000)['revision'],'command_id':'reissue'}
        first=await(await client.post(path+'/invitation/reissue',headers=headers,json=body)).json()
        again=await(await client.post(path+'/invitation/reissue',headers=headers,json=body)).json()
        assert first['invitation']==again['invitation']
        assert store.authenticate(c.client_id,newer.secret)

async def test_added_admin_is_verified_even_for_programmatic_settings_save(tmp_path):
    from server.app.setup import SetupService
    from tests.test_server_setup import Supervisor,draft
    supervisor=Supervisor();supervisor.options=draft()
    service=SetupService(tmp_path,supervisor)
    with pytest.raises(ValueError):
        await service.save({**draft(),'admin_user_ids':['admin','unverified']},service.revision(draft()))
    assert supervisor.writes==[]
