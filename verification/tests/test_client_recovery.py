import pytest
from server.app.pki import ensure_pki
from client.app.enrollment import save_credentials, load_credentials
import client.app.controller as module


def controller(tmp_path):
    data={'protocol':1,'client_id':'a'*32,'secret':'x'*43,'domain':'alpha.example.org',
          'server_url':'https://tunnel.example.org','tunnel_host':'tunnel.example.org','tunnel_port':7000,
          'ca_pem':ensure_pki(tmp_path/'pki','tunnel.example.org').ca.read_text()}
    save_credentials(tmp_path/'state',data)
    class Runtime:
        stopped=0
        async def stop(self): self.stopped+=1
        def status(self): return {'running':False}
    class Supervisor:
        async def restart_core(self): pytest.fail('Recovery must not restart Core')
    ctrl=module.Controller(tmp_path/'state',tmp_path/'configuration.yaml',Runtime(),Supervisor())
    ctrl.state='revoked'
    return ctrl,data


async def test_revoked_client_can_rebind_without_core_restart(tmp_path,monkeypatch):
    ctrl,old=controller(tmp_path)
    async def ready(*args): pass
    async def enroll(code,**expected):
        assert expected=={'expected_client_id':old['client_id'],'expected_server_url':old['server_url']}
        return {**old,'secret':'z'*43}
    async def launch(**kwargs): return True
    monkeypatch.setattr(module,'check_http_ready',ready)
    monkeypatch.setattr(module,'enroll',enroll)
    ctrl.launch=launch
    await ctrl.connect('new-code')
    assert ctrl.state=='connecting' and load_credentials(ctrl.directory)['secret']=='z'*43


async def test_explicit_other_connection_requires_confirmation(tmp_path,monkeypatch):
    ctrl,old=controller(tmp_path)
    async def unexpected(*args,**kwargs): pytest.fail('No code may be consumed without confirmation')
    monkeypatch.setattr(module,'enroll',unexpected)
    await ctrl.replace_connection('other-code',confirmed=False)
    assert load_credentials(ctrl.directory)==old and not ctrl.lock.locked()


async def test_failed_recovery_preserves_credentials(tmp_path,monkeypatch):
    ctrl,old=controller(tmp_path)
    async def ready(*args): pass
    async def broken(*args,**kwargs): raise OSError('network error with SECRET')
    monkeypatch.setattr(module,'check_http_ready',ready)
    monkeypatch.setattr(module,'enroll',broken)
    await ctrl.rebind('bad-code')
    assert ctrl.credentials==old and load_credentials(ctrl.directory)==old and not ctrl.lock.locked()
    assert 'SECRET' not in ctrl.message


async def test_confirmed_other_connection_clears_old_status(tmp_path,monkeypatch):
    ctrl,old=controller(tmp_path)
    ctrl.server_access={'access_state':'revoked'}
    ctrl.telemetry={'ha_available':False}
    async def ready(*args): pass
    async def enroll(code,**expected):
        assert expected=={}
        return {**old,'client_id':'b'*32,'domain':'beta.example.org','secret':'z'*43}
    async def launch(**kwargs): return True
    monkeypatch.setattr(module,'check_http_ready',ready)
    monkeypatch.setattr(module,'enroll',enroll)
    ctrl.launch=launch
    await ctrl.replace_connection('other-code',confirmed=True)
    assert load_credentials(ctrl.directory)['client_id']=='b'*32
    assert ctrl.server_access is None and ctrl.telemetry is None and ctrl.state=='connecting'


async def test_other_connection_api_requires_explicit_confirmation(tmp_path):
    import asyncio
    from aiohttp.test_utils import TestClient,TestServer
    from client.app.web import make_app
    class Controller:
        replacement=None
        def status(self): return {'configured':True,'state':'revoked'}
        async def replace_connection(self,invitation,*,confirmed):
            self.replacement=(invitation,confirmed)
    ctrl=Controller()
    async with TestClient(TestServer(make_app(ctrl,{'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner']}))) as client:
        headers={'X-Remote-User-Id':'owner'}
        state=await(await client.get('/api/state',headers=headers)).json()
        headers['X-CSRF-Token']=state['csrf']
        assert (await client.post('/api/replace-connection',headers=headers,json={'invitation':'new'})).status==400
        assert ctrl.replacement is None
        assert (await client.post('/api/replace-connection',headers=headers,json={'invitation':'new','confirmed':True})).status==202
        await asyncio.sleep(0)
        assert ctrl.replacement==('new',True)
