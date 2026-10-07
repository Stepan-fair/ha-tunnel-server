import copy
import json
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer


def state(config=None):
    return {'stable': config or {'server_port':8123, 'ip_ban_enabled':True,
            'trusted_proxies':['172.30.33.0/24'], 'created_at':'old', 'error':None,
            'error_message':None}, 'pending':None, 'active_config_type':'stable',
            'revert_at':None, 'default':{'server_port':80}}


class Core:
    def __init__(self, current=None):
        self.current=current or state()
        self.calls=[]
        self.wait_proxy_ready=AsyncMock()
    async def get_http_config(self): return copy.deepcopy(self.current)
    async def http_command(self, kind, **data):
        self.calls.append((kind,data))
        if kind=='http/config/configure':
            self.current['pending']={**data['config'],'created_at':'new','error':None,'error_message':None}
            self.current['active_config_type']='pending'
            self.current['revert_at']='future'
            return {'restart':True}
        if kind=='http/config/promote':
            self.current['stable']=self.current['pending']
            self.current['pending']=None
            self.current['active_config_type']='stable'
            self.current['revert_at']=None


async def test_modern_http_preserves_existing_access_and_does_not_touch_yaml(tmp_path):
    from client.app.http_config import configure_http,finish_http_trial,HTTPConfirmationRequired
    config=tmp_path/'configuration.yaml'; config.write_text('http: !secret deliberately_unread\n')
    original=config.read_bytes(); core=Core(); marker=tmp_path/'pending'
    with pytest.raises(HTTPConfirmationRequired):
        await configure_http(config,core,marker)
    changed=core.calls[0][1]['config']
    assert changed['trusted_proxies']==['172.30.33.0/24','127.0.0.1/32']
    assert changed['use_x_forwarded_for'] is True
    assert changed['server_port']==8123 and changed['ip_ban_enabled'] is True
    assert set(changed)=={'server_port','ip_ban_enabled','trusted_proxies','use_x_forwarded_for'}
    assert all(c[0]!='http/config/promote' for c in core.calls)
    core.wait_proxy_ready.assert_awaited()
    assert config.read_bytes()==original
    assert not await finish_http_trial(core,marker)
    core.current['stable']=core.current['pending']; core.current['pending']=None
    core.current['active_config_type']='stable'
    assert await finish_http_trial(core,marker)
    assert not marker.with_suffix('.http-api.json').exists()


async def test_modern_failure_never_promotes_and_keeps_retry_intent(tmp_path):
    from client.app.http_config import configure_http,HTTPConfirmationRequired
    core=Core(); core.wait_proxy_ready.side_effect=TimeoutError()
    marker=tmp_path/'pending'
    with pytest.raises(TimeoutError):
        await configure_http(tmp_path/'missing.yaml',core,marker,timeout=0.01)
    assert all(c[0]!='http/config/promote' for c in core.calls)
    assert marker.with_suffix('.http-api.json').exists()
    core.wait_proxy_ready.side_effect=None
    with pytest.raises(HTTPConfirmationRequired):
        await configure_http(tmp_path/'missing.yaml',core,marker)
    assert [c[0] for c in core.calls].count('http/config/configure')==1


async def test_foreign_pending_config_is_not_changed_or_promoted(tmp_path):
    from client.app.http_config import configure_http
    core=Core(); core.current['pending']={'server_port':8123,'trusted_proxies':['10.1.1.1']}
    with pytest.raises(ValueError):
        await configure_http(tmp_path/'x',core,tmp_path/'pending')
    assert not core.calls


async def test_concurrent_http_change_is_not_promoted(tmp_path):
    from client.app.http_config import configure_http
    core=Core()
    async def changed(**kwargs):
        core.current['pending']['trusted_proxies'].append('10.1.1.1')
    core.wait_proxy_ready.side_effect=changed
    with pytest.raises(ValueError):
        await configure_http(tmp_path/'x',core,tmp_path/'pending')
    assert all(c[0]!='http/config/promote' for c in core.calls)


@pytest.mark.parametrize('config',[
    {'server_port':8124}, {'server_port':8123,'ssl_certificate':'/ssl/cert.pem'},
    {'server_port':8123,'trusted_proxies':['0.0.0.0/0']},
    {'server_port':8123,'trusted_proxies':['::/0']},
])
async def test_unsupported_http_refuses_without_modification(tmp_path,config):
    from client.app.http_config import configure_http
    core=Core(state(config))
    with pytest.raises(ValueError):
        await configure_http(tmp_path/'x',core,tmp_path/'pending')
    assert not core.calls


async def test_ready_modern_resume_ignores_obsolete_yaml_and_does_not_write(tmp_path):
    from client.app.http_config import check_http_ready
    core=Core(state({'server_port':8123,'trusted_proxies':['127.0.0.1/32'],'use_x_forwarded_for':True}))
    await check_http_ready(tmp_path/'missing.yaml',core,tmp_path/'pending')
    assert not core.calls and list(tmp_path.iterdir())==[]


async def test_supervisor_ws_auth_and_only_unknown_command_falls_back(monkeypatch):
    from client.app import supervisor
    monkeypatch.setenv('SUPERVISOR_TOKEN','test-token')
    mode={'error':None}
    async def endpoint(request):
        assert request.headers['Authorization']=='Bearer test-token'
        ws=web.WebSocketResponse(); await ws.prepare(request)
        await ws.send_json({'type':'auth_required'})
        assert await ws.receive_json()=={'type':'auth','access_token':'test-token'}
        await ws.send_json({'type':'auth_ok'})
        msg=await ws.receive_json()
        assert msg['type']=='http/config'
        await ws.send_json({'id':msg['id'],'type':'result','success':mode['error'] is None,
            'result':state(),'error':{'code':mode['error'],'message':'test-token must not leak'}})
        await ws.close(); return ws
    app=web.Application(); app.router.add_get('/ws',endpoint)
    async with TestServer(app) as server:
        monkeypatch.setattr(supervisor,'CORE_WEBSOCKET',str(server.make_url('/ws')))
        client=supervisor.Supervisor()
        assert (await client.get_http_config())['stable']['server_port']==8123
        mode['error']='unknown_command'
        assert await client.get_http_config() is None
        mode['error']='unauthorized'
        with pytest.raises(ValueError) as error:
            await client.get_http_config()
        assert 'test-token' not in str(error.value)


async def test_ws_restart_disconnect_is_retryable(monkeypatch):
    from aiohttp import ClientConnectionError
    from client.app import supervisor
    monkeypatch.setenv('SUPERVISOR_TOKEN','test-token')
    async def endpoint(request):
        ws=web.WebSocketResponse(); await ws.prepare(request)
        await ws.send_json({'type':'auth_required'}); await ws.receive_json()
        await ws.send_json({'type':'auth_ok'}); await ws.receive_json()
        await ws.close(); return ws
    app=web.Application(); app.router.add_get('/ws',endpoint)
    async with TestServer(app) as server:
        monkeypatch.setattr(supervisor,'CORE_WEBSOCKET',str(server.make_url('/ws')))
        with pytest.raises(ClientConnectionError):
            await supervisor.Supervisor().get_http_config()


async def test_lost_configure_reply_keeps_waiting_for_own_trial(tmp_path):
    from aiohttp import ClientConnectionError
    from client.app.http_config import configure_http,HTTPConfirmationRequired
    core=Core(); command=core.http_command
    async def lost(kind,**data):
        await command(kind,**data)
        raise ClientConnectionError()
    core.http_command=lost
    with pytest.raises(HTTPConfirmationRequired):
        await configure_http(tmp_path/'x',core,tmp_path/'pending')
    assert len(core.calls)==1


async def test_resume_after_native_confirmation_recovers_without_ha_mutation(tmp_path):
    from client.app.controller import Controller
    from client.app.http_config import configure_http,HTTPConfirmationRequired
    core=Core(); pending=tmp_path/'ha-config.pending'
    with pytest.raises(HTTPConfirmationRequired):
        await configure_http(tmp_path/'x',core,pending)
    ctrl=Controller(tmp_path,tmp_path/'x',AsyncMock(),core)
    ctrl.credentials={'domain':'home.example.org'}; ctrl.launch=AsyncMock()
    await ctrl.resume()
    assert ctrl.state=='confirm_http'
    ctrl.launch.assert_not_awaited()
    core.current['stable']=core.current['pending']; core.current['pending']=None
    core.current['active_config_type']='stable'
    await ctrl.resume()
    ctrl.launch.assert_awaited_once()
    assert len(core.calls)==1


async def test_concurrent_edit_before_configure_is_preserved(tmp_path):
    from client.app.http_config import configure_http
    core=Core(); get=core.get_http_config; n=0
    async def changed():
        nonlocal n
        n+=1
        if n==2: core.current['pending']={'server_port':9999}
        return await get()
    core.get_http_config=changed
    with pytest.raises(ValueError):
        await configure_http(tmp_path/'x',core,tmp_path/'pending')
    assert core.calls==[]


@pytest.mark.parametrize('failure',['core','frp'])
async def test_confirmation_monitor_failure_keeps_client_panel_alive(tmp_path,failure):
    from client.app.controller import Controller
    from client.app.http_config import configure_http,HTTPConfirmationRequired
    from client.app.supervisor import CoreCommandError
    core=Core(); pending=tmp_path/'ha-config.pending'
    with pytest.raises(HTTPConfirmationRequired):
        await configure_http(tmp_path/'x',core,pending)
    ctrl=Controller(tmp_path,tmp_path/'x',AsyncMock(),core)
    ctrl.credentials={'domain':'home.example.org'}; ctrl.state='confirm_http'
    core.current['stable']=core.current['pending']; core.current['pending']=None
    core.current['active_config_type']='stable'
    ctrl.launch=AsyncMock(side_effect=RuntimeError('FRP rejected'))
    if failure=='core': core.get_http_config=AsyncMock(side_effect=CoreCommandError('unauthorized'))
    await ctrl.monitor_once()
    assert ctrl.state=='error' and ctrl.status()['configured']


async def test_reprepare_stops_own_existing_tunnel_before_http_trial(tmp_path):
    from client.app.controller import Controller
    core=Core(); runtime=AsyncMock()
    ctrl=Controller(tmp_path,tmp_path/'x',runtime,core)
    ctrl.credentials={'domain':'home.example.org'}
    await ctrl.connect(None)
    runtime.stop.assert_awaited_once()
    runtime.start.assert_not_awaited()
    assert ctrl.state=='confirm_http'
