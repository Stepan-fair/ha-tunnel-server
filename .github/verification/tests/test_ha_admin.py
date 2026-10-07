import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
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
