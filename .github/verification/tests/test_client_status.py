import pytest
from client.app.status import validate_status


@pytest.mark.parametrize('state', ['allowed','paused','expired','revoked','clock_error','pending'])
def test_access_status_validation(state):
    assert validate_status({'client_id': 'a'*32, 'access_state': state, 'revision': 1, 'generation': 0}, 'a'*32)['access_state'] == state
    with pytest.raises(ValueError):
        validate_status({'client_id': 'b'*32, 'access_state': state, 'revision': 1, 'generation': 0}, 'a'*32)


async def test_client_auto_resumes_after_pause(tmp_path, monkeypatch):
    from client.app.controller import Controller
    import client.app.controller as module
    class Runtime:
        running = True
        launches = 0
        async def stop(self): self.running = False
        def status(self): return {'running': self.running}
    runtime = Runtime()
    ctrl = Controller(tmp_path, tmp_path/'configuration.yaml', runtime, object())
    ctrl.credentials = {'client_id': 'a'*32, 'secret': 'x'*43, 'server_url': 'https://tunnel.example.org'}
    ctrl.state = 'connected'
    state = {'client_id': 'a'*32, 'access_state': 'paused', 'revision': 1, 'generation': 0}
    class Status:
        def __init__(self, url): pass
        async def fetch(self, *args): return dict(state)
    monkeypatch.setattr(module, 'ClientStatusClient', Status)
    async def tls(*args): pass
    monkeypatch.setattr(module, 'verify_tunnel_tls', tls)
    async def launch(**kwargs):
        runtime.running = True; runtime.launches += 1
    ctrl.launch = launch
    await ctrl.monitor_once()
    assert ctrl.state == 'paused' and not runtime.running and ctrl.credentials
    await ctrl.monitor_once()
    assert runtime.launches == 0
    state['access_state'] = 'allowed'
    await ctrl.monitor_once()
    assert runtime.running and runtime.launches == 1


async def test_status_unavailable_does_not_launch_from_cached_pause(tmp_path, monkeypatch):
    from client.app.controller import Controller
    import client.app.controller as module
    class Runtime:
        async def stop(self): pass
        async def start(self, config): pytest.fail('Cached permission must not start the tunnel')
        def status(self): return {'running': False}
    ctrl = Controller(tmp_path, tmp_path/'configuration.yaml', Runtime(), object())
    ctrl.credentials = {'client_id': 'a'*32, 'secret': 'x'*43, 'server_url': 'https://tunnel.example.org'}
    ctrl.state = 'paused'
    class Status:
        def __init__(self, url): pass
        async def fetch(self, *args): raise OSError('offline')
    monkeypatch.setattr(module, 'ClientStatusClient', Status)
    async def tls(*args): pass
    monkeypatch.setattr(module, 'verify_tunnel_tls', tls)
    await ctrl.monitor_once()
    assert ctrl.state == 'offline' and ctrl.credentials


async def test_old_server_fallback():
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from client.app.status import ClientStatusClient
    app=web.Application()
    async def health(request): return web.json_response({'status':'ok','protocol':1})
    app.router.add_get('/health',health)
    async with TestServer(app) as server:
        service=ClientStatusClient('https://tunnel.example.org')
        service.server_url=str(server.make_url('')).rstrip('/')
        try: assert await service.fetch('a'*32,'x'*43) is None
        finally: await service.close()


async def test_temporary_http_503_keeps_active_binding_and_later_refreshes(tmp_path, monkeypatch):
    from aiohttp import web, encode_basic_auth
    from aiohttp.test_utils import TestServer
    from unittest.mock import AsyncMock
    from client.app.status import ClientStatusClient
    from client.app.enrollment import load_credentials
    from tests.test_client_recovery import controller
    import client.app.controller as module

    ctrl, credentials = controller(tmp_path)
    ctrl.state = 'connected'
    ctrl.runtime.status = lambda: {'running': True}
    monkeypatch.setattr(module, 'verify_tunnel_tls', AsyncMock())
    monkeypatch.setattr(module, 'proxy_running', AsyncMock(return_value=True))
    revision = 1
    unavailable = False
    app = web.Application()
    async def status(request):
        assert request.headers['Authorization'] == encode_basic_auth(credentials['client_id'], credentials['secret'])
        assert await request.json() == {'capabilities': ['access-v1', 'telemetry-v1']}
        if unavailable: raise web.HTTPServiceUnavailable()
        return web.json_response({'client_id': credentials['client_id'], 'access_state': 'allowed',
                                  'revision': revision, 'generation': 0})
    app.router.add_post('/v1/client/status', status)
    async with TestServer(app) as server:
        ctrl.status_client = ClientStatusClient(credentials['server_url'])
        ctrl.status_client.server_url = str(server.make_url('')).rstrip('/')
        ctrl.status_origin = credentials['server_url']
        try:
            await ctrl.monitor_once()
            assert ctrl.state == 'connected' and ctrl.server_access['revision'] == 1
            unavailable = True
            await ctrl.monitor_once()
            assert ctrl.state == 'offline' and ctrl.billing_stale
            assert ctrl.runtime.status()['running'] and ctrl.runtime.stopped == 0
            assert ctrl.credentials == credentials and load_credentials(ctrl.directory) == credentials
            assert ctrl.server_access['revision'] == 1
            unavailable, revision = False, 2
            await ctrl.monitor_once()
            assert ctrl.state == 'connected' and not ctrl.billing_stale
            assert ctrl.server_access['revision'] == 2
            assert ctrl.runtime.stopped == 0 and load_credentials(ctrl.directory) == credentials
        finally:
            await ctrl.close()


async def test_043_health_first_status_contract_with_current_server(tmp_path):
    """Exact 0.4.3 request order/body, without importing an old runtime."""
    from aiohttp import encode_basic_auth
    from aiohttp.test_utils import TestClient, TestServer
    from tests.test_security_hardening import fixture
    from server.app.web import make_public_app
    store, credentials, authority, _ = fixture(tmp_path)
    identity = credentials.client_id
    async with TestClient(TestServer(make_public_app(store, authority,
            {'trusted_proxy_ips': ['127.0.0.1']}))) as client:
        proxy_headers = {'X-Forwarded-Proto': 'https'}
        health = await client.get('/health', headers=proxy_headers)
        assert health.status == 200
        discovery = await health.json()
        assert discovery['protocol'] == 1 and discovery['status'] == 'ok'
        assert 'access-v1' in discovery['capabilities']
        response = await client.post('/v1/client/status', headers={**proxy_headers,
            'Authorization': encode_basic_auth(identity, credentials.secret)},
            json={'capabilities': ['access-v1', 'telemetry-v1']})
        assert response.status == 200
        assert validate_status(await response.json(), identity)['client_id'] == identity
        assert store.status_authenticate(identity, credentials.secret) is not None


async def test_rebind_same_client_preserves_http_configuration(tmp_path,monkeypatch):
    from unittest.mock import AsyncMock
    from tests.test_client_recovery import controller
    from client.app.enrollment import save_credentials
    import client.app.controller as module
    ctrl,original=controller(tmp_path)
    replacement={**original,'secret':'z'*43}
    monkeypatch.setattr(module,'check_http_ready',AsyncMock())
    async def enroll(invitation,**kwargs):
        assert kwargs['expected_client_id']==original['client_id']
        assert kwargs['binding_secret']==original['secret']
        save_credentials(kwargs['directory'],replacement)
        return replacement
    monkeypatch.setattr(module,'enroll',enroll)
    ctrl.launch=AsyncMock(return_value=True)
    await ctrl.rebind('replacement-invitation')
    assert ctrl.credentials==replacement


async def test_rebind_wrong_server_is_rejected_before_network(monkeypatch):
    import client.app.enrollment as module
    from shared.protocol import Invitation
    def unexpected(*args,**kwargs): pytest.fail('No request may be made to the wrong server')
    monkeypatch.setattr(module,'ClientSession',unexpected)
    with pytest.raises(ValueError):
        await module.enroll(Invitation('https://other.example.org','x'*43).encode(),expected_client_id='a'*32,expected_server_url='https://tunnel.example.org')
