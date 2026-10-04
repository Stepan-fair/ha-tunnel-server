import time
from aiohttp import BasicAuth
from aiohttp.test_utils import TestClient, TestServer
from server.app.store import Store
from server.app.identity import Authority
from server.app.policy import authorize
from server.app.web import make_public_app


async def test_paused_status_allowed_token_denied(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    authority = Authority(tmp_path/'identity.key', 'http://127.0.0.1:19000')
    now = int(time.time())
    c = store.redeem(store.issue('alpha', now).code, now)
    options = {'trusted_proxy_ips': ['127.0.0.1']}
    headers = {'X-Forwarded-Proto': 'https'}
    auth = BasicAuth(c.client_id, c.secret)
    async with TestClient(TestServer(make_public_app(store, authority, options))) as client:
        response = await client.post('/v1/client/status', headers=headers, auth=auth, json={'capabilities': ['access-v1', 'telemetry-v1']})
        assert response.status == 200
        assert (await response.json())['access_state'] == 'allowed'
        store.apply_access(c.client_id, 'pause', 'pause', 0, now)
        response = await client.post('/v1/client/status', headers=headers, auth=auth, json={'capabilities': ['access-v1']})
        assert response.status == 200 and (await response.json())['access_state'] == 'paused'
        assert (await client.post('/v1/token', headers=headers, auth=auth, data={'grant_type': 'client_credentials'})).status == 401
        store.apply_access(c.client_id, 'start', 'start', 1, now)
        assert (await client.post('/v1/token', headers=headers, auth=auth, data={'grant_type': 'client_credentials'})).status == 200
        store.revoke(c.client_id)
        assert (await client.post('/v1/client/status', headers=headers, auth=auth, json={'capabilities': []})).status == 200
        replacement = store.redeem(store.reissue(c.client_id, now).code, now)
        assert (await client.post('/v1/client/status', headers=headers, auth=auth, json={'capabilities': []})).status == 401


def test_rebind_invalidates_old_generation(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    authority = Authority(tmp_path/'identity.key', 'http://127.0.0.1:19000')
    now = int(time.time())
    c = store.redeem(store.issue('alpha', now).code, now)
    old = authority.issue(c.client_id, generation=0)
    legacy = authority.issue(c.client_id)
    store.redeem(store.reissue(c.client_id, now).code, now)
    for token in (old, legacy):
        assert authorize('Login', {'user': c.client_id, 'privilege_key': token}, store, authority)['reject']
        for op in ('Ping', 'NewWorkConn'):
            assert authorize(op, {'user': {'user': c.client_id}, 'privilege_key': token}, store, authority)['reject']
    new = authority.issue(c.client_id, generation=1)
    login = authorize('Login', {'user': c.client_id, 'privilege_key': new, 'metas': {'ha_tunnel_generation': '0'}}, store, authority)
    assert not login['reject'] and login['content']['metas']['ha_tunnel_generation'] == '1'
    content = {'user': {'user': c.client_id, 'metas': {'ha_tunnel_generation': '0'}}, 'proxy_type': 'http', 'proxy_name': c.client_id+'.ha', 'custom_domains': [c.domain]}
    assert authorize('NewProxy', content, store, authority)['reject']
    content['user']['metas'] = login['content']['metas']
    assert not authorize('NewProxy', content, store, authority)['reject']


async def test_duration_preview_and_invitation_require_csrf(tmp_path):
    from server.app.web import make_ingress_app
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    invite=store.issue('alpha',2000)
    async def disconnect(cid): pass
    options={'server_url':'https://tunnel.example.org','admin_user_ids':['admin'],'ingress_ips':['127.0.0.1']}
    async with TestClient(TestServer(make_ingress_app(store,authority,options,disconnect))) as client:
        headers={'X-Remote-User-Id':'admin'}
        payload={'duration':{'minutes':20},'timezone':'Europe/Moscow'}
        assert (await client.post('/api/duration/preview',headers=headers,json=payload)).status==403
        state=await(await client.get('/api/state',headers=headers)).json()
        headers['X-CSRF-Token']=state['csrf']
        response=await client.post('/api/duration/preview',headers=headers,json=payload)
        assert response.status==200 and (await response.json())['deadline']==3200
        assert 'code' not in str(state) and 'invitation' not in str(state)
        response=await client.post('/api/clients/'+invite.client_id+'/invitation/show',headers=headers,json={})
        assert response.status==200 and (await response.json())['invitation'].startswith('HT1.')
        assert response.headers['Cache-Control']=='no-store'
