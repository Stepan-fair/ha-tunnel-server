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


async def test_old_server_fallback(monkeypatch):
    import client.app.status as module
    class Content:
        async def iter_chunked(self, size): yield b'{"status":"ok","protocol":1}'
    class Response:
        status=200
        content=Content()
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
    class Session:
        def __init__(self,**kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
        def get(self,*args,**kwargs):
            assert kwargs['allow_redirects'] is False
            return Response()
        def post(self,*args,**kwargs): pytest.fail('Legacy server has no status route')
    monkeypatch.setattr(module,'ClientSession',Session)
    assert await module.ClientStatusClient('https://tunnel.example.org').fetch('a'*32,'x'*43) is None


async def test_rebind_same_client_preserves_http_configuration(tmp_path,monkeypatch):
    from unittest.mock import AsyncMock
    import client.app.controller as module
    ctrl=module.Controller(tmp_path,tmp_path/'configuration.yaml',AsyncMock(),AsyncMock())
    original={'client_id':'a'*32,'domain':'alpha.example.org','server_url':'https://tunnel.example.org','secret':'old'}
    ctrl.credentials=original
    replacement={**original,'secret':'new','ca_pem':'PUBLIC'}
    monkeypatch.setattr(module,'check_http_ready',AsyncMock())
    monkeypatch.setattr(module,'enroll',AsyncMock(return_value=replacement))
    monkeypatch.setattr(module,'save_credentials',lambda *args:None)
    ctrl.launch=AsyncMock(return_value=True)
    await ctrl.rebind('replacement-invitation')
    assert ctrl.credentials==replacement
    module.enroll.assert_awaited_once_with('replacement-invitation',expected_client_id=original['client_id'],expected_server_url=original['server_url'])
    ctrl.supervisor.restart_core.assert_not_awaited()


async def test_rebind_wrong_server_is_rejected_before_network(monkeypatch):
    import client.app.enrollment as module
    from shared.protocol import Invitation
    def unexpected(*args,**kwargs): pytest.fail('No request may be made to the wrong server')
    monkeypatch.setattr(module,'ClientSession',unexpected)
    with pytest.raises(ValueError):
        await module.enroll(Invitation('https://other.example.org','x'*43).encode(),expected_client_id='a'*32,expected_server_url='https://tunnel.example.org')
