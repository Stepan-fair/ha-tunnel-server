import asyncio
import time
from aiohttp import encode_basic_auth
from aiohttp.test_utils import TestClient, TestServer
from server.app.store import Store
from server.app.identity import Authority
from server.app.policy import authorize
from server.app.web import make_public_app


async def test_status_busy_npm_refresh_is_temporary_and_preserves_binding(tmp_path):
    from server.app.npm_dependency import NpmRuntime, VerifiedNpmSnapshot, NPM_HOST

    class Dependency:
        hold = False
        def __init__(self):
            self.entered, self.release = asyncio.Event(), asyncio.Event()
        async def snapshot(self, options):
            assert options['npm_host'] == NPM_HOST
            if self.hold:
                self.entered.set()
                await self.release.wait()
            # Synthetic proxy for local HTTP only; production address validation stays intact.
            return VerifiedNpmSnapshot(NPM_HOST, ('127.0.0.1',), time.monotonic())

    class Gateway:
        running = False
        def revoke(self): self.running = False
        async def start(self, snapshot): self.running = True

    store = Store(tmp_path/'state.db', 'example.org', clock=lambda: 2000)
    credentials = store.redeem(store.issue('alpha', 2000).code, 2000)
    invitation = store.issue('beta', 2000)
    dependency = Dependency()
    runtime = NpmRuntime(dependency, {'npm_host': NPM_HOST}, store, Gateway())
    assert await runtime.refresh()
    headers = {'X-Forwarded-Proto': 'https',
               'Authorization': encode_basic_auth(credentials.client_id, credentials.secret)}
    body = {'capabilities': ['access-v1', 'telemetry-v1']}
    async with TestClient(TestServer(make_public_app(store, None, {'npm_runtime': runtime}))) as http:
        assert (await http.post('/v1/client/status', headers=headers, json=body)).status == 200
        before = store.access_snapshot(credentials.client_id, 2000)
        database = store.path.read_bytes()
        dependency.hold = True
        pending = asyncio.create_task(runtime.refresh())
        try:
            await asyncio.wait_for(dependency.entered.wait(), 2)
            assert store.administration.owner is pending
            assert store.administration.operation == 'npm_dependency'
            assert runtime.addresses == ('127.0.0.1',)
            response = await http.post('/v1/client/status', headers=headers, json=body)
            assert response.status == 503
            assert response.headers['Cache-Control'] == 'no-store'
            assert response.headers['Strict-Transport-Security'] == 'max-age=31536000'
            assert store.path.read_bytes() == database
            assert store.access_snapshot(credentials.client_id, 2000) == before
            assert store.status_authenticate(credentials.client_id, credentials.secret) is not None
            assert (await http.post('/v1/client/status', headers={'X-Forwarded-Proto': 'https'}, json=body)).status == 401
            assert (await http.post('/v1/enroll', headers=headers, json={'code': invitation.code})).status == 409
        finally:
            dependency.release.set()
            assert await asyncio.wait_for(pending, 2)
        assert not store.administration.busy
        assert (await http.post('/v1/client/status', headers=headers, json=body)).status == 200
        assert (await http.post('/v1/client/status', headers={'X-Forwarded-Proto': 'https'}, json=body)).status == 401
        assert (await http.post('/v1/client/status', headers=headers, data='{')).status == 400
        for malformed in ({}, {**body, 'extra': True}, {'capabilities': 'access-v1'},
                          {'capabilities': ['enrollment-v2']}, {'capabilities': ['access-v1']*3}, []):
            assert (await http.post('/v1/client/status', headers=headers, json=malformed)).status == 400


async def test_paused_status_allowed_token_denied(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    authority = Authority(tmp_path/'identity.key', 'http://127.0.0.1:19000')
    now = int(time.time())
    c = store.redeem(store.issue('alpha', now).code, now)
    options = {'trusted_proxy_ips': ['127.0.0.1']}
    headers = {'X-Forwarded-Proto': 'https','Authorization':encode_basic_auth(c.client_id,c.secret)}
    async with TestClient(TestServer(make_public_app(store, authority, options))) as client:
        response = await client.post('/v1/client/status', headers=headers, json={'capabilities': ['access-v1', 'telemetry-v1']})
        assert response.status == 200
        assert (await response.json())['access_state'] == 'allowed'
        store.apply_access(c.client_id, 'pause', 'pause', 0, now)
        response = await client.post('/v1/client/status', headers=headers, json={'capabilities': ['access-v1']})
        assert response.status == 200 and (await response.json())['access_state'] == 'paused'
        assert (await client.post('/v1/token', headers=headers, data={'grant_type': 'client_credentials'})).status == 401
        store.apply_access(c.client_id, 'start', 'start', 1, now)
        assert (await client.post('/v1/token', headers=headers, data={'grant_type': 'client_credentials'})).status == 200
        store.revoke(c.client_id)
        assert (await client.post('/v1/client/status', headers=headers, json={'capabilities': []})).status == 200
        replacement = store.redeem(store.reissue(c.client_id, now).code, now, binding=(c.client_id,c.secret))
        assert (await client.post('/v1/client/status', headers=headers, json={'capabilities': []})).status == 401


def test_rebind_invalidates_old_generation(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    authority = Authority(tmp_path/'identity.key', 'http://127.0.0.1:19000')
    now = int(time.time())
    c = store.redeem(store.issue('alpha', now).code, now)
    old = authority.issue(c.client_id, generation=0)
    legacy = authority.issue(c.client_id)
    store.redeem(store.reissue(c.client_id, now).code, now, binding=(c.client_id,c.secret))
    for token in (old, legacy):
        assert authorize('Login', {'user': c.client_id, 'privilege_key': token}, store, authority)['reject']
        for op in ('Ping', 'NewWorkConn'):
            assert authorize(op, {'user': {'user': c.client_id}, 'privilege_key': token}, store, authority)['reject']
    new = authority.issue(c.client_id, generation=1)
    login = authorize('Login', {'user': c.client_id, 'privilege_key': new, 'metas': {'ha_tunnel_generation': '0'}}, store, authority)
    assert not login['reject'] and login['content']['metas']['ha_tunnel_generation'] == '1'
    content = {'user': {'user': c.client_id, 'metas': {'ha_tunnel_generation': '0'}}, 'proxy_type': 'http', 'proxy_name': c.client_id+'.ha', 'custom_domains': [c.domain]}
    assert authorize('NewProxy', content, store, authority)['reject']
    content['user'] = {k:login['content'][k] for k in ('user','run_id','metas')}
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
