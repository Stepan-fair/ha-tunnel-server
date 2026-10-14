"""Recovery requirements with durable files and bounded real HTTP responses."""
import importlib.util
import json
import ssl

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient,TestServer
from server.app.pki import ensure_pki
from client.app.enrollment import save_credentials,load_credentials
from client.app.controller import Controller
import client.app.controller as controller_module
from client.app.status import ClientStatusClient
from client.app.web import make_app


class Runtime:
    def __init__(self): self.running=True; self.stops=0; self.starts=0
    async def stop(self): self.running=False; self.stops+=1
    async def start(self,config): self.running=True; self.starts+=1
    def status(self): return {'running':self.running}


@pytest.fixture
def configured(tmp_path):
    credentials={'protocol':1,'client_id':'a'*32,'secret':'x'*43,'domain':'alpha.example.org',
        'server_url':'https://tunnel.example.org','tunnel_host':'tunnel.example.org','tunnel_port':7000,
        'ca_pem':ensure_pki(tmp_path/'pki','tunnel.example.org').ca.read_text()}
    save_credentials(tmp_path/'state',credentials)
    ctrl=Controller(tmp_path/'state',tmp_path/'configuration.yaml',Runtime(),object())
    ctrl.state='connected'
    return ctrl,credentials


def test_legacy_file_migrates_without_network_or_secret_change(configured):
    ctrl,credentials=configured
    path=ctrl.directory/'credentials.json'
    path.write_text(json.dumps(credentials),encoding='utf-8')
    assert load_credentials(ctrl.directory)==credentials
    state=json.loads(path.read_bytes())
    assert state.get('schema')==2 and state['active']==credentials and state['pending_operation'] is None


async def test_corrupt_json_still_serves_ingress_and_keeps_original(tmp_path):
    path=tmp_path/'credentials.json'; path.write_bytes(b'{damaged')
    try: ctrl=Controller(tmp_path,tmp_path/'configuration.yaml',Runtime(),object())
    except Exception as exc: pytest.fail(f'Corruption prevented Ingress startup: {type(exc).__name__}')
    async with TestClient(TestServer(make_app(ctrl,{'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner']}))) as client:
        response=await client.get('/api/state',headers={'X-Remote-User-Id':'owner'})
        assert response.status==200 and (await response.json())['state']=='state_error'
    assert path.read_bytes()==b'{damaged'


def test_invalid_pending_preserves_valid_active_and_original(configured):
    ctrl,credentials=configured
    path=ctrl.directory/'credentials.json'
    original=json.dumps({'schema':2,'active':credentials,'pending_operation':{'stage':'commit_unknown'}}).encode()
    path.write_bytes(original)
    try: restored=Controller(ctrl.directory,ctrl.config_path,Runtime(),object())
    except Exception as exc: pytest.fail(f'Malformed pending discarded valid active: {type(exc).__name__}')
    assert restored.credentials==credentials
    assert restored.status()['binding_recovery'] is True
    assert path.read_bytes()==original


async def test_stale_initial_form_does_not_stop_running_tunnel(configured):
    ctrl,credentials=configured
    await ctrl.connect('stale-code')
    assert ctrl.runtime.running and ctrl.runtime.stops==0
    assert ctrl.credentials==credentials and ctrl.operation_error


async def test_status_and_billing_update_even_when_tunnel_tls_is_unavailable(configured,monkeypatch):
    ctrl,credentials=configured
    async def unavailable(*args): raise OSError('port unavailable')
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',unavailable)
    class Status:
        async def fetch(self,*args): return {'client_id':'a'*32,'access_state':'allowed','revision':7,'generation':0}
    ctrl.status_client=Status(); ctrl.status_origin=credentials['server_url']
    await ctrl.monitor_once()
    assert ctrl.server_access['revision']==7 and ctrl.billing_stale is False
    assert ctrl.state=='offline'


async def test_17280_failed_cycles_recover_without_new_code(configured,monkeypatch):
    ctrl,credentials=configured
    ctrl.runtime.running=False
    calls=0
    class Status:
        async def fetch(self,*args):
            nonlocal calls
            calls+=1
            if calls<=17280: raise OSError('offline')
            return {'client_id':'a'*32,'access_state':'allowed','revision':0,'generation':0}
    ctrl.status_client=Status(); ctrl.status_origin=credentials['server_url']
    async def tls(*args): pass
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',tls)
    for _ in range(17281): await ctrl.monitor_once()
    assert ctrl.runtime.starts==1 and ctrl.credentials==credentials


async def test_certificate_failure_stops_tunnel_but_recovers_after_trust_is_valid(configured,monkeypatch):
    ctrl,credentials=configured
    class Status:
        async def fetch(self,*args): return {'client_id':'a'*32,'access_state':'allowed','revision':0,'generation':0}
    ctrl.status_client=Status(); ctrl.status_origin=credentials['server_url']
    async def bad(*args): raise ssl.SSLCertVerificationError('untrusted')
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',bad)
    await ctrl.monitor_once()
    assert ctrl.state=='certificate_error' and not ctrl.runtime.running
    async def good(*args): pass
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',good)
    await ctrl.monitor_once()
    assert ctrl.runtime.running


async def test_authenticated_status_does_not_depend_on_exhausted_health_budget():
    app=web.Application()
    async def health(request): return web.Response(status=429)
    async def status(request): return web.json_response({'client_id':'a'*32,'access_state':'allowed','revision':9,'generation':1})
    app.router.add_get('/health',health); app.router.add_post('/v1/client/status',status)
    async with TestServer(app) as server:
        service=ClientStatusClient('https://tunnel.example.org')
        service.server_url=str(server.make_url('')).rstrip('/')
        try: result=await service.fetch('a'*32,'x'*43)
        except ValueError: pytest.fail('Anonymous health quota blocked authenticated status')
        finally: await service.close()
        assert result['revision']==9


async def test_rejected_status_stops_runtime_with_distinct_reason(configured,monkeypatch):
    import client.app.status as status_module
    assert hasattr(status_module,'CredentialsRejected'), '401 lacks typed credential rejection'
    ctrl,credentials=configured
    class Status:
        async def fetch(self,*args): raise status_module.CredentialsRejected()
    ctrl.status_client=Status(); ctrl.status_origin=credentials['server_url']
    async def tls(*args): pass
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',tls)
    await ctrl.monitor_once()
    assert not ctrl.runtime.running and ctrl.state=='credentials_rejected'

@pytest.fixture
def v2_environment(tmp_path,monkeypatch):
    import aiohttp
    import client.app.enrollment as module
    from tests.test_status_connections import LocalResolver
    from server.app.store import Store
    from server.app.identity import Authority
    from server.app.web import make_public_app
    pki=ensure_pki(tmp_path/'pki','tunnel.example.org')
    server_ssl=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_ssl.load_cert_chain(pki.cert,pki.key)
    client_ssl=ssl.create_default_context(cafile=pki.ca)
    address={}
    original_connection=controller_module.asyncio.open_connection
    async def tunnel_connection(host,port,**kwargs):
        assert host=='tunnel.example.org' and port==7000
        return await original_connection('127.0.0.1',address['port'],**kwargs)
    monkeypatch.setattr(controller_module.asyncio,'open_connection',tunnel_connection)
    original=aiohttp.ClientSession
    def session(**kwargs):
        return original(headers={'X-Forwarded-Proto':'https'},connector=aiohttp.TCPConnector(ssl=client_ssl,resolver=LocalResolver(address)),**kwargs)
    monkeypatch.setattr(module,'ClientSession',session)
    store=Store(tmp_path/'server.db','example.org')
    old=store.redeem(store.issue('alpha',store.now()).code,store.now())
    options={'server_url':'https://tunnel.example.org','tunnel_host':'tunnel.example.org','tunnel_port':7000,
        'ca_pem':pki.ca.read_text(),'trusted_proxy_ips':['127.0.0.1']}
    credentials={k:v for k,v in options.items() if k!='trusted_proxy_ips'}
    credentials.update(protocol=1,client_id=old.client_id,domain=old.domain,secret=old.secret)
    save_credentials(tmp_path/'state',credentials)
    app=make_public_app(store,Authority(tmp_path/'identity.key','http://127.0.0.1:19000'),options)
    return store,old,credentials,app,server_ssl,address,tmp_path/'state'


def binding_client(directory):
    import client.app.enrollment as module
    assert hasattr(module,'BindingClient'), 'Missing durable v2 enrollment client'
    return module.BindingClient(directory)


async def test_local_candidate_write_failure_never_commits(v2_environment,monkeypatch):
    from shared.protocol import Invitation
    import client.app.binding_state as module
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    client=binding_client(directory)
    original=module.atomic_write
    def fail_candidate(path,data,*args,**kwargs):
        if path.name=='credentials.json' and json.loads(data)['pending_operation']['candidate'] is not None:
            raise OSError('synthetic write failure')
        return original(path,data,*args,**kwargs)
    monkeypatch.setattr(module,'atomic_write',fail_candidate)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        code=store.reissue(old.client_id,store.now()).code
        with pytest.raises(OSError): await client.enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,expected_server_url=credentials['server_url'],binding_secret=old.secret)
        assert store.authenticate(old.client_id,old.secret)
        assert load_credentials(directory)==credentials
    finally: await server.close()


async def test_lost_commit_response_recovers_after_restart(v2_environment):
    from shared.protocol import Invitation
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    client=binding_client(directory)
    dropped=False
    @web.middleware
    async def lose_reply(request,handler):
        nonlocal dropped
        response=await handler(request)
        if request.path.endswith('/commit') and not dropped:
            dropped=True
            request.transport.close()
        return response
    app.middlewares.insert(0,lose_reply)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        code=store.reissue(old.client_id,store.now()).code
        import aiohttp
        with pytest.raises(aiohttp.ClientError): await client.enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,expected_server_url=credentials['server_url'],binding_secret=old.secret)
        pending=json.loads((directory/'credentials.json').read_bytes())['pending_operation']
        assert pending['stage']=='commit_unknown'
        assert store.authenticate(old.client_id,old.secret) is None
        recovered=await binding_client(directory).recover()
        assert recovered['client_id']==old.client_id and recovered['secret']==pending['secret']
        assert store.authenticate(old.client_id,recovered['secret'])
        assert json.loads((directory/'credentials.json').read_bytes())['pending_operation'] is None
        assert load_credentials(directory)==recovered
    finally: await server.close()


async def test_ca_write_failure_cannot_rotate_authority(v2_environment,monkeypatch):
    from shared.protocol import Invitation
    import client.app.binding_state as module
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    client=binding_client(directory)
    original=module.atomic_write
    def fail_ca(path,data,*args,**kwargs):
        if path.suffix=='.pem': raise OSError('synthetic CA failure')
        return original(path,data,*args,**kwargs)
    monkeypatch.setattr(module,'atomic_write',fail_ca)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        code=store.reissue(old.client_id,store.now()).code
        with pytest.raises(OSError): await client.enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,expected_server_url=credentials['server_url'],binding_secret=old.secret)
        assert store.authenticate(old.client_id,old.secret)
        assert load_credentials(directory)==credentials
    finally: await server.close()


def test_directory_fsync_failure_leaves_readable_authoritative_file(tmp_path,monkeypatch):
    import shared.files as module
    assert hasattr(module,'sync_directory'), 'Rename has no durability barrier'
    path=tmp_path/'state.json'; path.write_bytes(b'old')
    def fail(directory):
        if directory==path.parent: raise OSError('directory fsync failed')
    monkeypatch.setattr(module,'sync_directory',fail)
    with pytest.raises(OSError): module.atomic_write(path,b'new')
    assert path.read_bytes()==b'new'

async def test_transient_resume_error_keeps_automatic_retry(configured,monkeypatch):
    ctrl,credentials=configured
    async def ready(*args): pass
    class Supervisor:
        async def wait_proxy_ready(self,**kwargs): pass
    ctrl.supervisor=Supervisor()
    monkeypatch.setattr(controller_module,'check_http_ready',ready)
    async def temporary(*args,**kwargs): raise RuntimeError('FRP process temporarily unavailable')
    ctrl.launch=temporary
    from unittest.mock import AsyncMock
    ctrl.status_origin=credentials['server_url']
    ctrl.status_client=AsyncMock()
    ctrl.status_client.fetch.side_effect=OSError('Status API unavailable')
    await ctrl.resume()
    assert ctrl.state!='error'
    attempts=[]
    async def restored(*args,**kwargs): attempts.append(True); return True
    ctrl.launch=restored
    await ctrl.monitor_once()
    assert attempts


async def test_initial_connect_does_not_redeem_before_ha_is_ready(v2_environment,monkeypatch,tmp_path):
    from shared.protocol import Invitation
    from client.app.http_config import HTTPConfirmationRequired
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    new_directory=tmp_path/'new-state'
    ctrl=Controller(new_directory,tmp_path/'configuration.yaml',Runtime(),object())
    async def preview(*args): pass
    async def confirmation(*args): raise HTTPConfirmationRequired()
    monkeypatch.setattr(controller_module,'preview_http',preview)
    monkeypatch.setattr(controller_module,'configure_http',confirmation)
    invitation=store.issue('bravo',int(store.now()))
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        await ctrl.connect(Invitation(credentials['server_url'],invitation.code).encode())
        assert ctrl.state=='confirm_http'
        assert store.access_snapshot(invitation.client_id,store.now())['enrolled'] is False
        state=json.loads((new_directory/'credentials.json').read_bytes())
        assert state['pending_operation']['candidate']['client_id']==invitation.client_id
    finally: await ctrl.close(); await server.close()


async def test_controller_automatically_recovers_commit_unknown(v2_environment,monkeypatch,tmp_path):
    from shared.protocol import Invitation
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    @web.middleware
    async def lose_commit(request,handler):
        response=await handler(request)
        if request.path.endswith('/commit'): request.transport.close()
        return response
    app.middlewares.insert(0,lose_commit)
    class Supervisor:
        async def wait_proxy_ready(self,**kwargs): pass
    async def ready(*args): pass
    monkeypatch.setattr(controller_module,'check_http_ready',ready)
    ctrl=Controller(directory,tmp_path/'configuration.yaml',Runtime(),Supervisor()); ctrl.state='connected'
    async def launch(**kwargs): return True
    ctrl.launch=launch
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        invitation=store.reissue(old.client_id,int(store.now()))
        await ctrl.rebind(Invitation(credentials['server_url'],invitation.code).encode())
        assert ctrl.binding_recovery
        restored=Controller(directory,ctrl.config_path,Runtime(),Supervisor()); restored.launch=launch
        await restored.monitor_once()
        assert not restored.binding_recovery
        assert restored.credentials['secret']!=old.secret and store.authenticate(old.client_id,restored.credentials['secret'])
        await restored.close()
    finally: await ctrl.close(); await server.close()


async def test_pending_rejects_new_code_without_poisoning_recovery(v2_environment,monkeypatch,tmp_path):
    from shared.protocol import Invitation
    from client.app.http_config import HTTPConfirmationRequired
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    async def hold(): raise HTTPConfirmationRequired()
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        code=store.reissue(old.client_id,int(store.now())).code
        with pytest.raises(HTTPConfirmationRequired):
            await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret,before_commit=hold)
        before=(directory/'credentials.json').read_bytes()
        ctrl=Controller(directory,tmp_path/'configuration.yaml',Runtime(),object())
        await ctrl.rebind('another-code')
        assert ctrl.binding_recovery and ctrl.local_error is None
        assert (directory/'credentials.json').read_bytes()==before
    finally: await server.close()


async def test_missing_enrollment_capability_never_uses_v1(v2_environment):
    from shared.protocol import Invitation
    from client.app.enrollment import EnrollmentProblem
    store,old,credentials,_,server_ssl,address,directory=v2_environment
    app=web.Application(); v1=[]
    async def health(request): return web.json_response({'protocol':1,'status':'ok','capabilities':['access-v1']})
    async def legacy(request): v1.append(True); return web.json_response({})
    app.router.add_get('/health',health); app.router.add_post('/v1/enroll',legacy)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        with pytest.raises(EnrollmentProblem): await binding_client(directory).enroll(Invitation(credentials['server_url'],'c'*43).encode())
        assert not v1 and load_credentials(directory)==credentials
    finally: await server.close()


async def test_post_rename_failure_does_not_send_commit_and_retry_uses_saved_candidate(v2_environment,monkeypatch):
    from shared.protocol import Invitation
    import shared.files as files
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    original=files.sync_directory
    def fail_once(path):
        if path==directory:
            raw=json.loads((directory/'credentials.json').read_bytes())
            if raw['pending_operation'] and raw['pending_operation']['stage']=='commit_unknown':
                raise OSError('fsync after rename failed')
        original(path)
    monkeypatch.setattr(files,'sync_directory',fail_once)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        code=store.reissue(old.client_id,int(store.now())).code
        with pytest.raises(OSError): await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret)
        assert store.authenticate(old.client_id,old.secret)
        assert json.loads((directory/'credentials.json').read_bytes())['pending_operation']['stage']=='commit_unknown'
        monkeypatch.setattr(files,'sync_directory',original)
        result=await binding_client(directory).recover()
        assert store.authenticate(old.client_id,result['secret'])
    finally: await server.close()

async def test_pending_cancel_route_requires_ingress_and_csrf(configured):
    ctrl,_=configured
    async with TestClient(TestServer(make_app(ctrl,{'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner']}))) as client:
        headers={'X-Remote-User-Id':'owner'}
        state=await (await client.get('/api/state',headers=headers)).json()
        assert (await client.post('/api/binding/cancel',headers=headers,json={})).status==403
        headers['X-CSRF-Token']=state['csrf']
        assert (await client.post('/api/binding/cancel',headers=headers,json={})).status==202


async def test_replay_retention_expiry_can_confirm_committed_candidate(v2_environment):
    from shared.protocol import Invitation
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    @web.middleware
    async def lose_commit(request,handler):
        response=await handler(request)
        if request.path.endswith('/commit'): request.transport.close()
        return response
    app.middlewares.insert(0,lose_commit)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        import aiohttp
        code=store.reissue(old.client_id,int(store.now())).code
        with pytest.raises(aiohttp.ClientError): await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret)
        later=store.now()+86401; store.clock=lambda:later
        result=await binding_client(directory).recover()
        assert store.authenticate(old.client_id,result['secret'])
    finally: await server.close()


async def test_wrong_origin_rebind_sends_no_requests(v2_environment,monkeypatch):
    from shared.protocol import Invitation
    from client.app.enrollment import EnrollmentProblem
    import client.app.enrollment as module
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    def reject(*args,**kwargs): pytest.fail('Wrong-origin rebind must fail before creating any session')
    monkeypatch.setattr(module,'ClientSession',reject)
    with pytest.raises(EnrollmentProblem):
        await binding_client(directory).enroll(Invitation('https://other.example.org','c'*43).encode(),expected_client_id=old.client_id,expected_server_url=credentials['server_url'],binding_secret=old.secret)


async def test_explicit_other_connection_never_sends_existing_secret(v2_environment):
    from shared.protocol import Invitation
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    requests=[]
    @web.middleware
    async def record(request,handler):
        requests.append((request.path,request.headers.get('Authorization',''),await request.read()))
        return await handler(request)
    app.middlewares.insert(0,record)
    invite=store.issue('bravo',int(store.now()))
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        result=await binding_client(directory).enroll(Invitation(credentials['server_url'],invite.code).encode())
        assert result['client_id']==invite.client_id
        from aiohttp import encode_basic_auth
        old_header=encode_basic_auth(old.client_id,old.secret)
        assert all(old_header!=auth and old.secret.encode() not in body for _,auth,body in requests)
        assert next(auth for path,auth,_ in requests if path.endswith('/prepare'))==''
        assert store.authenticate(old.client_id,old.secret)
    finally: await server.close()

def test_legacy_migration_write_failure_preserves_readable_active(configured,monkeypatch):
    import client.app.binding_state as module
    ctrl,credentials=configured
    path=ctrl.directory/'credentials.json'
    original=json.dumps(credentials).encode(); path.write_bytes(original)
    def fail(*args,**kwargs): raise OSError('migration write failed')
    monkeypatch.setattr(module,'atomic_write',fail)
    try: loaded=module.StateFile(ctrl.directory).load()
    except module.StateProblem: pytest.fail('A valid legacy active binding must survive migration write failure')
    assert loaded.active==credentials and loaded.error
    assert path.read_bytes()==original


def test_new_directories_are_synced_before_atomic_write_returns(tmp_path,monkeypatch):
    import shared.files as module
    seen=[]
    monkeypatch.setattr(module,'sync_directory',lambda path:seen.append(path))
    path=tmp_path/'parent'/'state'/'credentials.json'
    module.atomic_write(path,b'{}')
    assert tmp_path in seen and tmp_path/'parent' in seen and path.parent in seen

async def test_committed_candidate_superseded_after_retention_does_not_block_new_operations(v2_environment):
    from shared.protocol import Invitation
    from client.app.status import CredentialsRejected
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    @web.middleware
    async def lose_commit(request,handler):
        response=await handler(request)
        if request.path.endswith('/commit'): request.transport.close()
        return response
    app.middlewares.insert(0,lose_commit)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        import aiohttp
        code=store.reissue(old.client_id,int(store.now())).code
        with pytest.raises(aiohttp.ClientError): await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret)
        snapshot=store.access_snapshot(old.client_id,store.now())
        transfer=store.reissue(old.client_id,int(store.now()),transfer=True,expected_revision=snapshot['revision'],confirm_domain=old.domain)
        replacement=store.redeem(transfer.code,int(store.now()))
        later=store.now()+86401; store.clock=lambda:later
        with pytest.raises(CredentialsRejected): await binding_client(directory).recover()
        assert json.loads((directory/'credentials.json').read_bytes())['pending_operation'] is None
        assert store.authenticate(old.client_id,replacement.secret)
    finally: await server.close()


async def test_failed_active_promotion_keeps_pending_for_next_start(v2_environment,monkeypatch):
    from shared.protocol import Invitation
    import client.app.binding_state as module
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    original=module.atomic_write
    def fail_promotion(path,data,*args,**kwargs):
        if path.name=='credentials.json':
            state=json.loads(data)
            if state['active'] and state['active']['secret']!=old.secret: raise OSError('promotion failed')
        return original(path,data,*args,**kwargs)
    monkeypatch.setattr(module,'atomic_write',fail_promotion)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        code=store.reissue(old.client_id,int(store.now())).code
        with pytest.raises(OSError): await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret)
        state=json.loads((directory/'credentials.json').read_bytes())
        assert state['pending_operation']['stage']=='commit_unknown' and state['active']==credentials
        monkeypatch.setattr(module,'atomic_write',original)
        result=await binding_client(directory).recover()
        assert store.authenticate(old.client_id,result['secret'])
    finally: await server.close()

async def test_status_401_is_a_typed_rejection_without_health_fallback():
    from client.app.status import CredentialsRejected
    app=web.Application(); health_requests=[]
    async def status(request): return web.Response(status=401)
    async def health(request): health_requests.append(True); return web.json_response({'status':'ok','protocol':1})
    app.router.add_post('/v1/client/status',status); app.router.add_get('/health',health)
    async with TestServer(app) as server:
        service=ClientStatusClient('https://tunnel.example.org'); service.server_url=str(server.make_url('')).rstrip('/')
        try:
            with pytest.raises(CredentialsRejected): await service.fetch('a'*32,'x'*43)
            assert not health_requests
        finally: await service.close()


async def test_cancel_uncommitted_candidate_is_confirmed_remotely(v2_environment):
    from shared.protocol import Invitation
    from client.app.http_config import HTTPConfirmationRequired
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    async def hold(): raise HTTPConfirmationRequired()
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        code=store.reissue(old.client_id,int(store.now())).code
        with pytest.raises(HTTPConfirmationRequired): await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret,before_commit=hold)
        assert await binding_client(directory).cancel()==credentials
        assert json.loads((directory/'credentials.json').read_bytes())['pending_operation'] is None
        assert store.authenticate(old.client_id,old.secret)
        assert store.redeem(code,int(store.now()),binding=(old.client_id,old.secret))
    finally: await server.close()


def test_oversized_state_is_not_silently_reset(configured):
    from client.app.binding_state import StateFile,StateProblem
    ctrl,_=configured
    path=ctrl.directory/'credentials.json'; raw=b' '*65537; path.write_bytes(raw)
    with pytest.raises(StateProblem): StateFile(ctrl.directory).load()
    assert path.read_bytes()==raw

async def test_cancel_before_prepare_reply_does_not_mark_valid_state_corrupt(configured):
    from client.app.binding_state import BindingState,StateFile
    ctrl,credentials=configured
    operation=dict(operation_id='b'*32,secret='z'*43,server_url=credentials['server_url'],code='c'*43,
        expected_client_id=credentials['client_id'],binding_secret=credentials['secret'],stage='prepare',
        candidate=None,server_instance_id=None,generation=None)
    StateFile(ctrl.directory).save(BindingState(credentials,operation))
    await ctrl._reload_binding()
    await ctrl.cancel_binding()
    assert ctrl.local_error is None and ctrl.binding_recovery

@pytest.mark.parametrize('transfer',[False,True])
@pytest.mark.parametrize('failure',[OSError,ssl.SSLCertVerificationError])
async def test_candidate_tunnel_handshake_failure_preserves_old_authority(v2_environment,monkeypatch,transfer,failure):
    from shared.protocol import Invitation
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    async def failed(candidate):
        assert candidate['client_id']==old.client_id and candidate['secret']!=old.secret
        raise failure('synthetic tunnel failure')
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',failed)
    current=store.access_snapshot(old.client_id,store.now())
    code=store.reissue(old.client_id,int(store.now()),transfer=transfer,expected_revision=current['revision'],confirm_domain=old.domain).code
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        with pytest.raises(failure):
            await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),
                **({} if transfer else {'expected_client_id':old.client_id,'binding_secret':old.secret}))
        assert store.authenticate(old.client_id,old.secret)
        assert load_credentials(directory)==credentials
        pending=json.loads((directory/'credentials.json').read_bytes())['pending_operation']
        assert pending['stage']=='prepared'
        assert store.status_authenticate(old.client_id,pending['secret']) is None
    finally: await server.close()


async def test_committed_recovery_does_not_wait_for_tunnel_or_ha(v2_environment,monkeypatch):
    from shared.protocol import Invitation
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    @web.middleware
    async def lose_commit(request,handler):
        response=await handler(request)
        if request.path.endswith('/commit'): request.transport.close()
        return response
    app.middlewares.insert(0,lose_commit)
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        import aiohttp
        code=store.reissue(old.client_id,int(store.now())).code
        with pytest.raises(aiohttp.ClientError): await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret)
        async def unavailable(*args): raise OSError('HA or FRP still offline')
        monkeypatch.setattr(controller_module,'verify_tunnel_tls',unavailable)
        recovered=await binding_client(directory).recover(before_commit=unavailable)
        assert store.authenticate(old.client_id,recovered['secret'])
        assert json.loads((directory/'credentials.json').read_bytes())['pending_operation'] is None
    finally: await server.close()

async def test_real_candidate_tls_rejects_other_ca_without_committing(v2_environment,tmp_path):
    from shared.protocol import Invitation
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    other_ca=ensure_pki(tmp_path/'other-pki','tunnel.example.org').ca.read_text()
    @web.middleware
    async def wrong_ca(request,handler):
        response=await handler(request)
        if request.path.endswith('/prepare') and response.status==200:
            data=json.loads(response.body); data['credentials']['ca_pem']=other_ca
            return web.json_response(data)
        return response
    app.middlewares.insert(0,wrong_ca)
    current=store.access_snapshot(old.client_id,store.now())
    code=store.reissue(old.client_id,int(store.now()),transfer=True,expected_revision=current['revision'],confirm_domain=old.domain).code
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode())
        assert store.authenticate(old.client_id,old.secret)
        assert load_credentials(directory)==credentials
    finally: await server.close()


async def test_expired_candidate_clears_only_after_server_confirmation(v2_environment,monkeypatch):
    from shared.protocol import Invitation
    from client.app.enrollment import EnrollmentProblem
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    async def offline(*args): raise OSError('port offline')
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',offline)
    code=store.reissue(old.client_id,int(store.now())).code
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        with pytest.raises(OSError): await binding_client(directory).enroll(Invitation(credentials['server_url'],code).encode(),expected_client_id=old.client_id,binding_secret=old.secret)
        later=store.now()+901; store.clock=lambda:later
        with pytest.raises(EnrollmentProblem): await binding_client(directory).recover()
        assert json.loads((directory/'credentials.json').read_bytes())['pending_operation'] is None
        assert store.authenticate(old.client_id,old.secret)
    finally: await server.close()

@pytest.mark.parametrize('location',['active','pending'])
def test_certificate_without_ca_extension_is_typed_local_corruption(configured,location):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    ctrl,credentials=configured
    ca=x509.load_pem_x509_certificate(credentials['ca_pem'].encode())
    key=serialization.load_pem_private_key((ctrl.directory.parent/'pki/ca.key').read_bytes(),password=None)
    malformed=(x509.CertificateBuilder().subject_name(ca.subject).issuer_name(ca.issuer)
        .public_key(ca.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(ca.not_valid_before_utc).not_valid_after(ca.not_valid_after_utc)
        .sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    invalid={**credentials,'ca_pem':malformed}
    pending=None
    if location=='pending':
        pending=dict(operation_id='b'*32,secret=credentials['secret'],server_url=credentials['server_url'],code='c'*43,
            expected_client_id=credentials['client_id'],binding_secret=credentials['secret'],stage='prepared',
            candidate=invalid,server_instance_id='d'*32,generation=1)
    raw=json.dumps({'schema':2,'active':invalid if location=='active' else credentials,'pending_operation':pending}).encode()
    (ctrl.directory/'credentials.json').write_bytes(raw)
    try: restored=Controller(ctrl.directory,ctrl.config_path,Runtime(),object())
    except Exception as exc: pytest.fail(f'Certificate corruption stopped Ingress: {type(exc).__name__}')
    assert restored.binding_recovery and restored.local_error
    assert restored.credentials==(None if location=='active' else credentials)
    assert (ctrl.directory/'credentials.json').read_bytes()==raw


def test_retry_after_directory_creation_sync_failure_repeats_parent_barrier(tmp_path,monkeypatch):
    import shared.files as module
    target=tmp_path/'parent'/'state'/'credentials.json'
    def fail(path):
        if path==tmp_path: raise OSError('parent persistence failed')
    monkeypatch.setattr(module,'sync_directory',fail)
    with pytest.raises(OSError): module.atomic_write(target,b'{}')
    assert target.parent.is_dir() and not target.exists()
    seen=[]
    monkeypatch.setattr(module,'sync_directory',lambda path:seen.append(path))
    module.atomic_write(target,b'{}')
    assert tmp_path in seen and tmp_path/'parent' in seen
    assert seen.index(tmp_path)<seen.index(tmp_path/'parent')<seen.index(target.parent)


@pytest.mark.parametrize('ha_failure',['waiting_ha','configuration_error'])
async def test_protected_status_updates_while_ha_blocks_runtime(v2_environment,monkeypatch,ha_failure):
    import aiohttp
    from client.app.ha_config import ConfigProblem
    from server.app.billing import BillingRepository
    from tests.test_billing_store import command
    from tests.test_status_connections import LocalResolver
    store,old,credentials,app,server_ssl,address,directory=v2_environment
    requests=[]
    @web.middleware
    async def count_status(request,handler):
        if request.path=='/v1/client/status': requests.append(request.headers.get('Authorization'))
        return await handler(request)
    app.middlewares.insert(0,count_status)
    async def unavailable(*args):
        if ha_failure=='configuration_error': raise ConfigProblem('HTTP needs manual repair')
        raise OSError('HA unavailable')
    monkeypatch.setattr(controller_module,'check_http_ready',unavailable)
    ctrl=Controller(directory,directory/'configuration.yaml',Runtime(),object())
    ctrl.runtime.running=False
    service=ClientStatusClient(credentials['server_url'])
    service.session=aiohttp.ClientSession(headers={'X-Forwarded-Proto':'https'},
        connector=aiohttp.TCPConnector(ssl=ssl.create_default_context(cadata=credentials['ca_pem']),resolver=LocalResolver(address)),trust_env=False)
    ctrl.status_client=service; ctrl.status_origin=credentials['server_url']
    server=TestServer(app,scheme='https'); await server.start_server(ssl=server_ssl); address['port']=server.port
    try:
        await ctrl.resume()
        assert ctrl.server_access is not None, 'HA failure suppressed authenticated status'
        assert ctrl.server_access['access_state']=='allowed' and not ctrl.billing_stale
        assert ctrl.state==ha_failure and ctrl.runtime.starts==0
        for index in range(3):
            command(BillingRepository(store),old.client_id,'topup',100,store.now())
            await ctrl.monitor_once()
            assert ctrl.server_access['billing']['balance_kopecks']==(index+1)*100
            assert ctrl.runtime.starts==0 and not ctrl.runtime.running
        for action,expected in [('pause','paused'),('start','allowed')]:
            snap=store.access_snapshot(old.client_id,store.now())
            store.apply_access(old.client_id,action,action,snap['revision'],store.now())
            await ctrl.monitor_once()
            assert ctrl.server_access['access_state']==expected
            assert ctrl.runtime.starts==0 and not ctrl.runtime.running
        # Readiness recovery is automatic only for transient HA failures.
        async def ready(*args): pass
        class Supervisor:
            async def wait_proxy_ready(self,**kwargs): pass
        monkeypatch.setattr(controller_module,'check_http_ready',ready)
        ctrl.supervisor=Supervisor()
        await ctrl.monitor_once()
        if ha_failure=='configuration_error':
            assert ctrl.runtime.starts==0
            await ctrl.resume()
        assert ctrl.runtime.starts==1 and ctrl.runtime.running
        # Revoke and 401 must remain observable after HA becomes unavailable again.
        await ctrl.runtime.stop()
        monkeypatch.setattr(controller_module,'check_http_ready',unavailable)
        await ctrl.resume()
        store.revoke(old.client_id)
        await ctrl.monitor_once()
        assert ctrl.server_access['access_state']=='revoked' and ctrl.runtime.starts==1
        # A later rebind rejects this secret; local HA failure must not hide 401.
        code=store.reissue(old.client_id,store.now()).code
        store.redeem(code,store.now(),old.client_id,binding=(old.client_id,old.secret))
        await ctrl.monitor_once()
        assert ctrl.state=='credentials_rejected' and ctrl.runtime.starts==1
        ctrl.set_state('disconnected','Manually disconnected')
        previous=len(requests)
        await ctrl.monitor_once()
        assert len(requests)==previous and ctrl.runtime.starts==1
        assert all(value for value in requests)
    finally:
        await ctrl.close()
        await server.close()


@pytest.mark.parametrize('previous_gate',['configuration_error','waiting_ha'])
@pytest.mark.parametrize('access_at_confirmation',['allowed','paused'])
async def test_manual_http_trial_replaces_old_gate_and_completes_after_confirmation(configured,monkeypatch,previous_gate,access_at_confirmation):
    from tests.test_http_api_config import Core
    ctrl,credentials=configured
    core=Core(); ctrl.supervisor=core
    ctrl.runtime.running=False
    current={'access_state':'allowed','revision':0}
    class Status:
        async def fetch(self,*args):
            return {'client_id':credentials['client_id'],'generation':0,**current}
    ctrl.status_client=Status(); ctrl.status_origin=credentials['server_url']
    original_get=core.get_http_config
    async def unavailable(): raise OSError('HA temporarily unavailable')
    if previous_gate=='waiting_ha': core.get_http_config=unavailable
    await ctrl.resume()
    assert ctrl.state==previous_gate
    await ctrl.monitor_once()
    assert not core.calls and ctrl.runtime.starts==0, 'Recovery must not edit HA automatically'
    core.get_http_config=original_get
    await ctrl.connect(None)
    assert ctrl.state=='confirm_http' and core.current['active_config_type']=='pending'
    assert ctrl.runtime.starts==0
    async def unexpected_tls(*args): pytest.fail('Unconfirmed HTTP trial reached runtime connection path')
    monkeypatch.setattr(controller_module,'verify_tunnel_tls',unexpected_tls)
    for access in ('allowed','paused','allowed'):
        current['access_state']=access; current['revision']+=1
        await ctrl.monitor_once()
        assert ctrl.server_access['revision']==current['revision']
        assert not ctrl.runtime.running and ctrl.runtime.starts==0
        assert core.current['active_config_type']=='pending'
    ctrl.set_state('disconnected','Manually disconnected')
    current['revision']+=1
    await ctrl.monitor_once()
    assert ctrl.server_access['revision']!=current['revision'] and ctrl.runtime.starts==0
    await ctrl.connect(None)
    assert ctrl.state=='confirm_http' and ctrl.runtime.starts==0
    current['access_state']=access_at_confirmation
    # Only the owner's native HA confirmation promotes the candidate config.
    core.current['stable']=core.current['pending']; core.current['pending']=None
    core.current['active_config_type']='stable'; core.current['revert_at']=None
    await ctrl.monitor_once()
    if access_at_confirmation=='paused':
        assert ctrl.state=='paused' and ctrl.runtime.starts==0
        current['access_state']='allowed'
        async def verified_tls(*args): pass
        monkeypatch.setattr(controller_module,'verify_tunnel_tls',verified_tls)
        await ctrl.monitor_once()
    assert ctrl.runtime.starts==1 and ctrl.runtime.running
    assert ctrl.state=='connecting'
    assert [kind for kind,_ in core.calls]==['http/config/configure']
    assert not ctrl.pending_path.with_suffix('.http-api.json').exists()
