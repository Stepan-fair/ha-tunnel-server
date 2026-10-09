import importlib
import time
from pathlib import Path
import pytest
from aiohttp.test_utils import TestClient, TestServer
from server.app.store import Store
from server.app.identity import Authority


@pytest.fixture
def setup(tmp_path):
    assert Path('server/app/web.py').exists(), 'HTTP apps not implemented'
    from server.app.web import make_public_app, make_plugin_app, make_ingress_app
    store = Store(tmp_path/'state.db', 'example.com')
    authority = Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    options = {'server_url':'https://tunnel.example.com','tunnel_host':'tunnel.example.com',
               'tunnel_port':7000,'ca_pem':'PUBLIC CA', 'trusted_proxy_ips':['127.0.0.1'],
               'admin_user_ids':['admin-id'], 'ingress_ips':['127.0.0.1']}
    return store, authority, options, make_public_app, make_plugin_app, make_ingress_app


async def test_public_does_not_expose_admin_or_plugin(setup):
    s,a,o,p,plugin,admin = setup
    async with TestClient(TestServer(p(s,a,o))) as c:
        for route in ['/','/clients','/v1/clients','/handler','/jwks','/export']:
            r = await c.get(route, headers={'X-Forwarded-Proto':'https','X-Remote-User-Id':'admin-id'})
            assert r.status in (403,404,405)


async def test_public_requires_trusted_source_and_https(setup):
    s,a,o,p,plugin,admin = setup
    code = s.issue(None,int(time.time())).code
    async with TestClient(TestServer(p(s,a,o))) as c:
        assert (await c.post('/v1/enroll',json={'code':code})).status == 403
    o['trusted_proxy_ips'] = ['192.0.2.1']
    async with TestClient(TestServer(p(s,a,o))) as c:
        assert (await c.post('/v1/enroll',json={'code':code},headers={'X-Forwarded-Proto':'https'})).status == 403


async def test_enroll_and_oauth_tokens_are_individual(setup):
    s,a,o,p,plugin,admin = setup
    code = s.issue('house',int(time.time())).code
    async with TestClient(TestServer(p(s,a,o))) as c:
        headers={'X-Forwarded-Proto':'https'}
        r=await c.post('/v1/enroll',json={'code':code},headers=headers)
        assert r.status == 200
        data=await r.json()
        assert data['domain']=='house.example.com' and data['ca_pem']=='PUBLIC CA'
        assert r.headers['Cache-Control']=='no-store'
        assert (await c.post('/v1/enroll',json={'code':code},headers=headers)).status==400
        from aiohttp import encode_basic_auth
        headers['Authorization']=encode_basic_auth(data['client_id'],data['secret'])
        token=await c.post('/v1/token',data={'grant_type':'client_credentials'},headers=headers)
        assert token.status==200
        assert a.subject((await token.json())['access_token'])==data['client_id']
        s.revoke(data['client_id'])
        assert (await c.post('/v1/token',data={'grant_type':'client_credentials'},headers=headers)).status==401


async def test_rebind_wrong_identity_does_not_consume_invitation(setup):
    s,a,o,p,plugin,admin = setup
    now=int(time.time())
    alpha=s.redeem(s.issue('alpha',now).code,now)
    bravo=s.redeem(s.issue('bravo',now).code,now)
    invite=s.reissue(bravo.client_id,now)
    before=s.list_clients()
    async with TestClient(TestServer(p(s,a,o))) as client:
        headers={'X-Forwarded-Proto':'https'}
        response=await client.post('/v1/enroll',headers=headers,json={'code':invite.code,'expected_client_id':alpha.client_id})
        assert response.status==400
        assert s.list_clients()==before
        assert s.authenticate(bravo.client_id,bravo.secret)
        response=await client.post('/v1/enroll',headers=headers,json={'code':invite.code,'expected_client_id':bravo.client_id})
        assert response.status==200
        assert (await response.json())['client_id']==bravo.client_id


async def test_ingress_identity_csrf_and_revoke(setup):
    s,a,o,p,plugin,admin = setup
    revoked=[]
    async def disconnect(client_id):
        s.revoke(client_id)
        revoked.append(client_id)
    async with TestClient(TestServer(admin(s,a,o,disconnect))) as c:
        assert (await c.get('/')).status==403
        assert (await c.get('/',headers={'X-Remote-User-Id':'other'})).status==403
        headers={'X-Remote-User-Id':'admin-id'}
        r=await c.get('/api/state',headers=headers)
        assert r.status==200
        state=await r.json()
        assert (await c.post('/api/clients',json={},headers=headers)).status==403
        headers['X-CSRF-Token']=state['csrf']
        r=await c.post('/api/clients',json={},headers=headers)
        data=await r.json()
        assert r.status==200 and data['invitation'].startswith('HT1.')
        assert (await c.get('/api/clients/'+data['client_id']+'/revoke',headers=headers)).status==405
        r=await c.post('/api/clients/'+data['client_id']+'/revoke',json={},headers=headers)
        assert r.status==200 and revoked==[data['client_id']]


async def test_request_size_invalid_json_and_rate_limit(setup):
    s,a,o,p,plugin,admin = setup
    async with TestClient(TestServer(p(s,a,o))) as c:
        headers={'X-Forwarded-Proto':'https','Content-Type':'application/json'}
        assert (await c.post('/v1/enroll',data='x'*9000,headers=headers)).status==413
        assert (await c.post('/v1/enroll',data='not json',headers=headers)).status==400
        statuses=[]
        for _ in range(25):
            statuses.append((await c.post('/v1/enroll',json={'code':'bad'},headers={'X-Forwarded-Proto':'https'})).status)
        assert 429 in statuses


async def test_token_rejects_multipart_before_creating_temporary_files(setup,monkeypatch):
    import tempfile
    from aiohttp import FormData, encode_basic_auth
    s,a,o,p,plugin,admin=setup
    now=int(time.time())
    credentials=s.redeem(s.issue('multipart-test',now).code,now)
    opened=[]
    original=tempfile.TemporaryFile
    def temporary(*args,**kwargs):
        opened.append(True)
        return original(*args,**kwargs)
    monkeypatch.setattr(tempfile,'TemporaryFile',temporary)
    form=FormData()
    form.add_field('grant_type','client_credentials')
    for index in range(4): form.add_field(f'file{index}',b'',filename='test-only')
    headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(credentials.client_id,credentials.secret)}
    async with TestClient(TestServer(p(s,a,o))) as client:
        response=await client.post('/v1/token',data=form,headers=headers)
        assert response.status==415
        assert opened==[], 'OAuth token endpoint must never allocate multipart files'
        response=await client.post('/v1/token',data={'grant_type':'client_credentials'},headers=headers)
        assert response.status==200
