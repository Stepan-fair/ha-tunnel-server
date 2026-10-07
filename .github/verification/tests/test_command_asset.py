from pathlib import Path
from aiohttp.test_utils import TestClient,TestServer
from server.app.store import Store
from server.app.identity import Authority
from server.app.web import make_ingress_app
from tools.release_repository import release_repository

async def test_command_helper_served_only_to_verified_ingress_admin(tmp_path):
    store=Store(tmp_path/'state.db','example.org')
    authority=Authority(tmp_path/'identity.key','http://localhost')
    async def admin(user): return user=='admin'
    async def disconnect(cid): pass
    options={'server_url':'https://tunnel.example.org','admin_user_ids':['admin'],'ingress_ips':['127.0.0.1']}
    async with TestClient(TestServer(make_ingress_app(store,authority,options,disconnect,admin_check=admin))) as client:
        assert (await client.get('/command_id.js')).status==403
        response=await client.get('/command_id.js',headers={'X-Remote-User-Id':'admin'})
        assert response.status==200
        assert response.content_type=='text/javascript'
        assert await response.read()==Path('server/app/templates/command_id.js').read_bytes()

def test_javascript_regression_is_in_generated_verification_context(tmp_path):
    package=tmp_path/'server-release'
    release_repository('server',package)
    assert (package/'.github/verification/tests/command_id.test.cjs').read_bytes()==Path('tests/command_id.test.cjs').read_bytes()
