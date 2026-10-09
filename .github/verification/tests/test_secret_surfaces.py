"""Real synthetic credentials must never appear on routine UI/read surfaces."""
import time
from unittest.mock import AsyncMock

from aiohttp.test_utils import TestClient, TestServer

from client.app.controller import Controller
from client.app.enrollment import save_credentials
from client.app.web import make_app
from server.app.identity import Authority
from server.app.pki import ensure_pki
from server.app.store import Store
from server.app.web import make_ingress_app, make_public_app
from shared.diagnostics import Diagnostics


async def test_routine_pages_state_logs_and_public_routes_exclude_private_material(tmp_path):
    now=int(time.time())
    store=Store(tmp_path/'server/state.db','example.org')
    invitation=store.issue('alpha',now)
    credentials=store.redeem(invitation.code,now)
    pending=store.issue('pending',now)
    authority=Authority(tmp_path/'server/identity.key','http://127.0.0.1:19000')
    pki=ensure_pki(tmp_path/'server/pki','tunnel.example.org')
    forbidden=[credentials.secret.encode(),pending.code.encode(),
               (tmp_path/'server/identity.key').read_bytes(),pki.key.read_bytes(),
               b'-----BEGIN PRIVATE KEY-----',b'-----BEGIN RSA PRIVATE KEY-----']
    log=Diagnostics(tmp_path/'server/logs')
    log.failure('startup_error',ValueError(credentials.secret+pending.code),component='server')
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],
             'server_url':'https://tunnel.example.org','trusted_proxy_ips':['127.0.0.1']}
    async def disconnect(client_id): pass
    responses=[]
    async with TestClient(TestServer(make_ingress_app(store,authority,options,disconnect,diagnostics=log))) as client:
        for path in ('/','/app.js','/style.css','/api/state','/api/diagnostics','/api/diagnostics/export','/api/help'):
            response=await client.get(path,headers={'X-Remote-User-Id':'owner'})
            assert response.status==200,path
            responses.append(await response.read())
            assert response.headers['Cache-Control']=='no-store'
    async with TestClient(TestServer(make_public_app(store,authority,options))) as client:
        for path in ('/health','/api/state','/api/diagnostics','/api/backup/export','/identity.key','/pki/ca.key'):
            response=await client.get(path,headers={'X-Forwarded-Proto':'https','X-Remote-User-Id':'owner'})
            assert response.status==(200 if path=='/health' else 404)
            responses.append(await response.read())
    client_dir=tmp_path/'client'
    save_credentials(client_dir,{'protocol':1,'client_id':credentials.client_id,'secret':credentials.secret,
        'domain':credentials.domain,'server_url':'https://tunnel.example.org',
        'tunnel_host':'tunnel.example.org','tunnel_port':7000,'ca_pem':pki.ca.read_text()})
    controller=Controller(client_dir,tmp_path/'configuration.yaml',AsyncMock(),AsyncMock())
    async with TestClient(TestServer(make_app(controller,options))) as client:
        for path in ('/','/app.js','/style.css','/api/state','/api/help'):
            response=await client.get(path,headers={'X-Remote-User-Id':'owner'})
            assert response.status==200,path
            responses.append(await response.read())
    responses.extend(path.read_bytes() for path in (tmp_path/'server/logs').glob('*') if path.is_file())
    assert all(secret not in response for secret in forbidden for response in responses)
    log.handler.close()
