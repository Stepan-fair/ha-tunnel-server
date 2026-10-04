import asyncio
import pytest
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer


async def test_controller_retains_credentials_after_ha_error_and_never_publishes(tmp_path):
    from client.app.controller import Controller
    from server.app.pki import ensure_pki
    from client.app.enrollment import save_credentials
    config=tmp_path/'configuration.yaml'
    config.write_text('default_config:\n')
    data={'protocol':1,'client_id':'a'*32,'secret':'x'*43,'domain':'home.example.org',
          'server_url':'https://tunnel.example.org','tunnel_host':'tunnel.example.org','tunnel_port':7000,
          'ca_pem':ensure_pki(tmp_path/'pki','tunnel.example.org').ca.read_text()}
    save_credentials(tmp_path/'state',data)
    class Runtime:
        started=False
        async def start(self,c): self.started=True
        async def stop(self): pass
        def status(self): return {'running':self.started}
    class Supervisor:
        async def get_http_config(self): return None
        async def check_config(self): return False
        async def restart_core(self): pytest.fail('Must not restart')
        async def wait_ready(self): pass
    runtime=Runtime()
    controller=Controller(tmp_path/'state',config,runtime,Supervisor())
    await controller.connect(None)
    assert controller.status()['state']=='error'
    assert controller.status()['configured']
    assert not runtime.started
    assert 'x'*43 not in str(controller.status())
    assert config.read_text()=='default_config:\n'


async def test_dashboard_probe_reports_proxy_not_just_process(tmp_path):
    from client.app.controller import proxy_running
    from aiohttp import BasicAuth
    app=web.Application()
    # FRP 0.71's client dashboard reports the local proxy name, without user prefix.
    state={'http':[{'name':'ha','status':'running'}]}
    async def handler(request):
        assert request.headers.get('Authorization')
        return web.json_response(state)
    app.router.add_get('/api/status',handler)
    async with TestServer(app) as server:
        assert await proxy_running(str(server.make_url('/api/status')),'password','abc')
        state['http'][0]['status']='error'
        assert not await proxy_running(str(server.make_url('/api/status')),'password','abc')


async def test_client_admin_routes_require_identity_and_csrf(tmp_path):
    from client.app.web import make_app
    from aiohttp.test_utils import TestClient
    class Controller:
        requested=[]
        def status(self): return {'state':'disconnected','configured':False}
        async def connect(self,code): self.requested.append(code)
    ctrl=Controller()
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['admin']}
    async with TestClient(TestServer(make_app(ctrl,options))) as client:
        assert (await client.get('/api/state')).status==403
        headers={'X-Remote-User-Id':'admin'}
        data=await (await client.get('/api/state',headers=headers)).json()
        assert (await client.post('/api/connect',json={'invitation':'test'},headers=headers)).status==403
        headers['X-CSRF-Token']=data['csrf']
        assert (await client.post('/api/connect',json={'invitation':'test'},headers=headers)).status==202
        await asyncio.sleep(0)
        assert ctrl.requested==['test']
