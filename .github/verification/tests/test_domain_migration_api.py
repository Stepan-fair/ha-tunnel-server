import pytest
from aiohttp.test_utils import TestClient,TestServer
from server.app.web import make_ingress_app
from server.app.identity import Authority
from tests.test_domain_migration import context

async def test_domain_migration_api_replay_and_csrf(tmp_path):
    store,creds,repo,now,snap,setup,migration,draft=context(tmp_path)
    authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    options={**setup.options,'ingress_ips':['127.0.0.1']}
    async def disconnect(cid):pass
    app=make_ingress_app(store,authority,options,disconnect,setup=setup,migration=migration)
    async with TestClient(TestServer(app)) as client:
        headers={'X-Remote-User-Id':'admin'}
        assert (await client.post('/api/domain-migration/preview',headers=headers,json={'draft':draft})).status==403
        state=await(await client.get('/api/state',headers=headers)).json()
        headers['X-CSRF-Token']=state['csrf']
        response=await client.post('/api/domain-migration/preview',headers=headers,json={'draft':draft})
        assert response.status==200
        preview=await response.json()
        assert 'secret' not in str(preview) and preview['readiness']['ready']
        body=dict(draft=draft,command_id='api-move',revision=preview['revision'])
        response=await client.post('/api/domain-migration/apply',headers=headers,json=body)
        assert response.status==200 and (await response.json())['phase']=='committed'
        assert (await client.post('/api/domain-migration/apply',headers=headers,json=body)).status==200
