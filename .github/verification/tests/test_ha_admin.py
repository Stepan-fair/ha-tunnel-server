import asyncio
import re
import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from shared.ha_admin import verified_admin


@pytest.mark.parametrize('user,allowed',[
    ({'id':'admin','is_active':True,'group_ids':['system-admin']},True),
    ({'id':'admin','is_active':True,'is_owner':True},True),
    ({'id':'admin','is_active':True,'group_ids':['system-users']},False),
    ({'id':'admin','is_active':False,'is_owner':True},False),
    ({'id':'admin','is_active':True,'is_owner':True,'system_generated':True},False),
    ({'id':'other','is_active':True,'is_owner':True},False),
])
async def test_actual_ha_role_protocol(monkeypatch,user,allowed):
    async def handler(request):
        ws=web.WebSocketResponse(); await ws.prepare(request)
        await ws.send_json({'type':'auth_required'})
        assert await ws.receive_json()=={'type':'auth','access_token':'test-token'}
        await ws.send_json({'type':'auth_ok'})
        assert await ws.receive_json()=={'id':1,'type':'config/auth/list'}
        await ws.send_json({'id':1,'type':'result','success':True,'result':[user]})
        await ws.close(); return ws
    app=web.Application(); app.router.add_get('/core/websocket',handler)
    async with TestServer(app) as server:
        original=aiohttp.ClientSession.ws_connect
        def connect(session,url,**kwargs):
            assert url=='http://supervisor/core/websocket'
            return original(session,str(server.make_url('/core/websocket')),**kwargs)
        monkeypatch.setattr(aiohttp.ClientSession,'ws_connect',connect)
        assert await verified_admin('admin','test-token') is allowed


async def test_admin_missing_credentials_is_closed():
    assert not await verified_admin('admin','')
    assert not await verified_admin('','token')


@pytest.mark.parametrize('role', ['server', 'setup', 'client'])
async def test_concurrent_ingress_assets_verify_admin_over_real_dns(monkeypatch, tmp_path, role):
    """A browser loads scripts together; a numeric fixture hid DNS contention."""
    calls = []
    active = [True]

    async def core(request):
        calls.append(True)
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({'type': 'auth_required'})
        assert await ws.receive_json() == {'type': 'auth', 'access_token': 'test-token'}
        await ws.send_json({'type': 'auth_ok'})
        assert await ws.receive_json() == {'id': 1, 'type': 'config/auth/list'}
        await ws.send_json({'id': 1, 'success': True, 'result': [
            {'id': 'admin', 'is_active': active[0], 'is_owner': True}]})
        await ws.close()
        return ws

    supervisor = web.Application()
    supervisor.router.add_get('/core/websocket', core)
    async with TestServer(supervisor) as server:
        original = aiohttp.ClientSession.ws_connect
        def connect(session, url, **kwargs):
            assert url == 'http://supervisor/core/websocket'
            return original(session, str(server.make_url('/core/websocket').with_host('localhost')), **kwargs)
        monkeypatch.setattr(aiohttp.ClientSession, 'ws_connect', connect)
        async def admin(user):
            return await verified_admin(user, 'test-token')
        options = {'ingress_ips': ['127.0.0.1'], 'server_url': 'https://tunnel.example.org'}
        if role == 'server':
            from server.app.web import make_ingress_app
            from server.app.store import Store
            from server.app.identity import Authority
            store = Store(tmp_path/'state.db', 'example.org')
            authority = Authority(tmp_path/'identity.key', options['server_url'])
            async def disconnect(client): pass
            app = make_ingress_app(store, authority, options, disconnect, admin_check=admin)
        elif role == 'setup':
            from server.app.setup import SetupService, make_setup_app
            app = make_setup_app(SetupService(tmp_path, object()), admin, ingress_ips=['127.0.0.1'])
        else:
            from client.app.web import make_app
            app = make_app(object(), options, admin_check=admin)
        async with TestClient(TestServer(app)) as browser:
            headers = {'X-Remote-User-Id': 'admin'}
            index = await browser.get('/', headers=headers)
            assert index.status == 200
            html = await index.text()
            names = re.findall(r'<script[^>]+src="([^"]+)"', html) + ['style.css']
            assert len(names) >= 3
            replies = await asyncio.gather(*(browser.get('/'+name, headers={
                'X-Remote-User-Id': 'admin'}) for name in names))
            assert [reply.status for reply in replies] == [200] * len(names)
            assert all(reply.content_type == ('text/css' if name.endswith('.css') else 'text/javascript')
                       for name, reply in zip(names, replies))
            assert len(calls) == len(names) + 1, 'each asset still verifies current HA authorization'
            # No authorization cache, bypass for assets, or weakened write guard.
            active[0] = False
            assert (await browser.get('/app.js', headers=headers)).status == 403
            assert (await browser.get('/app.js')).status == 403
            active[0] = True
            assert (await browser.post('/api/setup', headers=headers, json={})).status == 403
