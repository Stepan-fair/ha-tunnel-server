import pytest
from aiohttp.test_utils import TestClient, TestServer
from server.app.web import make_ingress_app, make_public_app
from server.app.store import Store
from server.app.identity import Authority
from shared.diagnostics import Diagnostics


async def test_diagnostics_admin_only_bounded_and_private(tmp_path):
    store = Store(tmp_path/'state.db','example.org')
    authority = Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    log = Diagnostics(tmp_path/'logs')
    log.failure('startup_error', ValueError('private-password'), component='server')
    options = {'admin_user_ids':['admin'],'ingress_ips':['127.0.0.1']}
    async def disconnect(cid): pass
    app = make_ingress_app(store,authority,options,disconnect,diagnostics=log)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get('/api/diagnostics')).status == 403
        assert (await client.get('/api/diagnostics',headers={'X-Remote-User-Id':'other'})).status == 403
        headers = {'X-Remote-User-Id':'admin'}
        response = await client.get('/api/diagnostics?limit=5',headers=headers)
        assert response.status == 200
        data = await response.json()
        assert data['summary']['last_failure']['code'] == 'startup_error'
        assert len(data['items']) <= 5
        assert response.headers['Cache-Control'] == 'no-store'
        assert (await client.get('/api/diagnostics?limit=1001',headers=headers)).status == 400
        exported = await (await client.get('/api/diagnostics/export',headers=headers)).text()
        assert 'private-password' not in exported and 'startup_error' in exported
    async with TestClient(TestServer(make_public_app(store,authority,{'trusted_proxy_ips':['127.0.0.1']}))) as client:
        assert (await client.get('/api/diagnostics',headers={'X-Forwarded-Proto':'https','X-Remote-User-Id':'admin'})).status == 404
