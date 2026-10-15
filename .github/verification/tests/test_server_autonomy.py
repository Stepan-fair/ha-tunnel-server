import asyncio
import time
from aiohttp import encode_basic_auth,ClientSession
from aiohttp.test_utils import TestClient,TestServer
import pytest
from server.app.store import Store
from server.app.identity import Authority
from server.app.web import make_public_app
from test_npm_dependency import runtime_case,HOST

async def test_dependency_wait_is_503_then_same_client_recovers_without_credential_rejection(tmp_path,monkeypatch):
    from client.app.controller import Controller
    from client.app.status import ClientStatusClient
    from client.app.enrollment import save_credentials
    from server.app.pki import ensure_pki
    from test_client_autonomy import Runtime
    import client.app.controller as client_module
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    # Inject only address ownership network boundary; loopback transports replace Docker/NPM.
    from server.app.npm_dependency import VerifiedNpmSnapshot
    async def snapshot(options):
        if sup.error: raise ValueError('Supervisor unavailable')
        return VerifiedNpmSnapshot(HOST,('127.0.0.1',),time.monotonic())
    runtime.dependency.snapshot=snapshot
    now=int(time.time()); c=store.redeem(store.issue('alpha',now).code,now)
    authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    creds=dict(protocol=1,client_id=c.client_id,secret=c.secret,domain=c.domain,server_url='https://tunnel.example.org',
        tunnel_host='tunnel.example.org',tunnel_port=7000,ca_pem=ensure_pki(tmp_path/'pki','tunnel.example.org').ca.read_text())
    save_credentials(tmp_path/'client',creds)
    ctrl=Controller(tmp_path/'client',tmp_path/'configuration.yaml',Runtime(),object()); ctrl.state='connected'
    async def tls(*args): pass
    async def published(*args): return True
    monkeypatch.setattr(client_module,'verify_tunnel_tls',tls); monkeypatch.setattr(client_module,'proxy_running',published)
    options={'trusted_proxy_ips':[],'npm_runtime':runtime}
    def preserved():
        return [{k:v for k,v in row.items() if k!='capabilities'} for row in store.list_clients()]
    before=preserved()
    async with TestClient(TestServer(make_public_app(store,authority,options))) as client:
        ctrl.status_client=ClientStatusClient(creds['server_url']); ctrl.status_origin=creds['server_url']
        ctrl.status_client.server_url=str(client.make_url('')).rstrip('/')
        ctrl.status_client.session=ClientSession(headers={'X-Forwarded-Proto':'https'})
        try:
            for available in (False,True,False,True):
                sup.error=not available; await runtime.refresh()
                response=await client.post('/v1/client/status',headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(c.client_id,c.secret)},json={'capabilities':[]})
                assert response.status==(200 if available else 503)
                await ctrl.monitor_once()
                assert ctrl.state==('connected' if available else 'offline')
                assert ctrl.credentials==creds
            assert (await client.get('/health')).status==403
        finally: await ctrl.close(); await gateway.close()
    assert preserved()==before

async def test_probe_uses_current_snapshot_and_never_caches_revoked_success(tmp_path,monkeypatch):
    from server.app.availability_probe import ServiceProbe
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    class FRP:
        def status(self): return {'running':False}
    probe=ServiceProbe(FRP(),gateway,'https://tunnel.example.org',lambda:runtime.addresses)
    assert await runtime.refresh()
    assert probe.addresses==('172.30.33.9',)
    probe.last=True; probe.at=time.monotonic()
    sup.error=True; await runtime.refresh()
    assert probe.addresses==()
    assert (await probe())['npm'] is False
    await gateway.close()

async def test_valid_startup_with_dns_absent_enters_supervised_operation_not_setup(tmp_path,monkeypatch):
    from server.app import main
    from server.app.setup import SetupService
    from test_npm_dependency import Supervisor,Resolver
    import json
    options=dict(base_domain='example.org',server_url='https://tunnel.example.org',npm_host=HOST,admin_user_ids=['admin'])
    (tmp_path/'options.json').write_text(json.dumps(options))
    service=SetupService(tmp_path,Supervisor()); service.options=options
    async def detect(): return service.snapshot()
    service.detect=detect
    original_path=main.Path
    monkeypatch.setattr(main,'Path',lambda value:tmp_path/'options.json' if str(value)=='/data/options.json' else original_path(value))
    monkeypatch.setattr(main,'SetupService',lambda *a,**kw:service)
    def fail_dns(*a,**kw): raise OSError('late DNS')
    import socket
    monkeypatch.setattr(socket,'getaddrinfo',fail_dns)
    observed=[]
    async def operation(*args): observed.append('operational'); return False
    async def setup(*args): observed.append('setup'); return False
    monkeypatch.setattr(main,'run_operational',operation); monkeypatch.setattr(main,'run_setup',setup)
    try: await main._main()
    except OSError: observed.append('crashed')
    assert observed==['operational']


async def test_setup_snapshot_exposes_dependency_and_external_unknown(tmp_path,monkeypatch):
    from server.app.setup import SetupService
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    setup=SetupService(tmp_path,sup); setup.dependency_status=runtime.status
    assert setup.snapshot()['dependency']=={'state':'waiting_dependency','reason':'waiting_dependency','local_ready':False,'local_health':'unhealthy','external':'unknown'}
    await runtime.refresh()
    assert setup.snapshot()['dependency']['local_ready'] is True
    await gateway.close()

@pytest.mark.parametrize('npm_first',[False,True])
async def test_actual_operational_lifecycle_keeps_ingress_clock_and_retries(tmp_path,monkeypatch,npm_first):
    from server.app import main
    from server.app.setup import SetupService
    from server.app.relay import ClientRelay
    from server.app.npm_dependency import NpmDependency
    from test_npm_dependency import Supervisor,Resolver,Process
    import server.app.gateway as gateway_module
    options=dict(base_domain='example.org',server_url='https://tunnel.example.org',npm_host=HOST,admin_user_ids=['admin'],ingress_ips=['127.0.0.1'])
    sup=Supervisor(); sup.error=not npm_first; resolve=Resolver()
    setup=SetupService(tmp_path,sup); setup.options={k:v for k,v in options.items() if k!='ingress_ips'}
    setup.npm_dependency=NpmDependency(sup,resolve)
    stopped=asyncio.Event(); runners={}; processes=[]; observations=[]
    class Runner:
        def __init__(self,server): self.server=server
        async def cleanup(self): await self.server.close()
    async def listen(app,host,port):
        server=TestServer(app); await server.start_server(); runners[port]=server; return Runner(server)
    async def launch(*a,**kw): p=Process(); processes.append(p); return p
    class FRP:
        def __init__(self,*a,**kw): self.running=False
        async def start(self,*a): self.running=True
        async def stop(self): self.running=False
        async def restart(self): self.running=True
        def status(self): return {'running':self.running}
    class ClockSupervisor:
        async def get(self,path): observations.append(path); return {'dt_synchronized':True}
    async def mqtt(*args): return None
    async def admin(*args): return True
    original_start=ClientRelay.start
    async def relay_start(self,*args): await original_start(self,port=0)
    monkeypatch.setattr(main,'listen',listen); monkeypatch.setattr(main,'shutdown_event',stopped.wait)
    monkeypatch.setattr(main,'HEALTH_PATH',tmp_path/'health'); monkeypatch.setattr(main,'ServerRuntime',FRP)
    monkeypatch.setattr(main,'SupervisorClient',lambda *a:ClockSupervisor()); monkeypatch.setattr(main,'verified_admin',admin)
    monkeypatch.setattr(main,'mqtt_service',mqtt); monkeypatch.setattr(ClientRelay,'start',relay_start)
    monkeypatch.setattr(gateway_module.asyncio,'create_subprocess_exec',launch)
    monkeypatch.setattr(gateway_module,'kill_gateway',lambda process:process.kill())
    task=asyncio.create_task(main.run_operational(options,setup))
    try:
        async with asyncio.timeout(3):
            while 8099 not in runners or not (tmp_path/'health').exists():
                if task.done(): await task
                await asyncio.sleep(.01)
        async with ClientSession() as client:
            async with client.get(runners[8099].make_url('/api/state'),headers={'X-Remote-User-Id':'admin'}) as response:
                state=await response.json(); assert response.status==200
                assert state['dependency']['external']=='unknown'
                assert state['dependency']['local_ready'] is npm_first
            assert '/host/info' in observations
            sup.error=False
            async with asyncio.timeout(7):
                while not setup.dependency_status()['local_ready']: await asyncio.sleep(.02)
            assert processes and processes[-1].returncode is None
            assert 0<=time.monotonic()-float((tmp_path/'health').read_text())<10
        stopped.set(); assert await task is False
        assert all(server.closed for server in runners.values())
        assert all(p.returncode is not None for p in processes)
        assert not setup.administration.busy
    finally:
        task.cancel(); await asyncio.gather(task,return_exceptions=True)

async def test_probe_discards_success_if_dependency_revoked_during_last_await(monkeypatch):
    from server.app.availability_probe import ServiceProbe
    import server.app.availability_probe as probe_module
    addresses=['172.30.33.9']
    class FRP:
        def status(self): return {'running':False}
    class Gateway: returncode=None
    class Response:
        status=403
        async def __aenter__(self): addresses.clear(); return self
        async def __aexit__(self,*a): pass
    class Session:
        def __init__(self,*a,**kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self,*a): pass
        def get(self,*a,**kw): return Response()
    monkeypatch.setattr(probe_module,'ClientSession',Session)
    probe=ServiceProbe(FRP(),Gateway(),'https://tunnel.example.org',lambda:addresses)
    probe.last_addresses=tuple(addresses);probe.last_generation=0;probe.last=True;probe.at=time.monotonic()
    assert (await probe())['npm'] is False

async def test_changed_npm_peer_before_refresh_is_transient_not_credentials_rejection(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    await runtime.refresh()  # Current proof points to Docker, request arrives from new loopback peer.
    authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    async with TestClient(TestServer(make_public_app(store,authority,{'npm_runtime':runtime}))) as client:
        response=await client.post('/v1/client/status',headers={'X-Forwarded-Proto':'https'},json={'capabilities':[]})
        assert response.status==503
    await gateway.close()

async def test_probe_invalidates_cache_after_same_address_gateway_replacement(monkeypatch):
    from server.app.availability_probe import ServiceProbe
    import server.app.availability_probe as module
    epoch=[1]; addresses=['172.30.33.9']
    class FRP:
        def status(self): return {'running':False}
    class Gateway: returncode=1
    class OfflineSession:
        def __init__(self,*a,**kw): self.connector=kw['connector']
        async def __aenter__(self): await self.connector.close(); raise OSError('NPM not ready after replacement')
        async def __aexit__(self,*a): pass
    monkeypatch.setattr(module,'ClientSession',OfflineSession)
    probe=ServiceProbe(FRP(),Gateway(),'https://tunnel.example.org',lambda:addresses,generation=lambda:epoch[0])
    probe.last_addresses=tuple(addresses);probe.last_generation=1;probe.last=True;probe.at=time.monotonic()
    epoch[0]=2
    assert (await probe())['npm'] is False

async def test_delayed_core_authorization_recovers_on_same_ingress_listener(tmp_path,monkeypatch):
    import aiohttp
    from aiohttp import web
    from shared.ha_admin import verified_admin
    from server.app.setup import SetupService,make_setup_app
    from test_npm_dependency import Supervisor
    ready=False
    async def core(request):
        if not ready: return web.Response(status=503)
        ws=web.WebSocketResponse();await ws.prepare(request)
        await ws.send_json({'type':'auth_required'})
        assert await ws.receive_json()=={'type':'auth','access_token':'test-token'}
        await ws.send_json({'type':'auth_ok'})
        assert await ws.receive_json()=={'id':1,'type':'config/auth/list'}
        await ws.send_json({'id':1,'success':True,'result':[{'id':'admin','is_active':True,'is_owner':True}]})
        await ws.close();return ws
    app=web.Application();app.router.add_get('/core/websocket',core)
    async with TestServer(app) as upstream:
        original=aiohttp.ClientSession.ws_connect
        def connect(session,url,**kwargs):
            assert url=='http://supervisor/core/websocket'
            return original(session,str(upstream.make_url('/core/websocket')),**kwargs)
        monkeypatch.setattr(aiohttp.ClientSession,'ws_connect',connect)
        async def admin(user): return await verified_admin(user,'test-token')
        service=SetupService(tmp_path,Supervisor())
        async with TestClient(TestServer(make_setup_app(service,admin,ingress_ips=['127.0.0.1']))) as client:
            headers={'X-Remote-User-Id':'admin'}
            assert (await client.get('/api/setup',headers=headers)).status==403
            ready=True
            assert (await client.get('/api/setup',headers=headers)).status==200

async def test_delayed_mqtt_service_retries_existing_worker_without_restart(monkeypatch):
    from shared.mqtt import MqttBridge
    from shared.supervisor_services import MqttService
    import shared.mqtt as mqtt_module
    import threading
    loop=asyncio.get_running_loop(); stopped=threading.Event()
    ready=False; connected=asyncio.Event()
    async def provider():
        if not ready: raise ValueError('Supervisor late')
        return MqttService('127.0.0.1',1883,'user','test-secret',False)
    class Client:
        def __init__(self,*a,**kw): pass
        def username_pw_set(self,*a): pass
        def will_set(self,*a,**kw): pass
        def max_queued_messages_set(self,*a): pass
        def max_inflight_messages_set(self,*a): pass
        def connect(self,*a,**kw): loop.call_soon_threadsafe(connected.set)
        def loop_forever(self,*a,**kw): stopped.wait()
        def disconnect(self): stopped.set()
    monkeypatch.setattr(mqtt_module.mqtt,'Client',Client)
    bridge=MqttBridge('a'*32,'server',provider,lambda:[])
    await bridge.start(); worker=bridge.task
    try:
        assert bridge.status()['state']=='service_error'
        ready=True;bridge.next_retry=0
        await bridge.queue.put(('disconnect',))
        await asyncio.wait_for(connected.wait(),2)
        assert bridge.task is worker and bridge.status()['state']=='connecting'
    finally: await bridge.close()
    assert worker.done()
