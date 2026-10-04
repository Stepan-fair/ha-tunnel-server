"""Run in the isolated Linux test image; never points to a real HA or router."""
import asyncio
import json
from contextlib import AsyncExitStack
import os
from pathlib import Path
import shutil
import socket
import ssl
import time

import pytest
from aiohttp import web,ClientSession,ClientError,ClientTimeout,WSMsgType
from aiohttp.test_utils import TestServer
from shared.runtime import FrpRuntime
from server.app.store import Store
from server.app.identity import Authority
from server.app.pki import ensure_pki
from server.app.runtime import ServerRuntime,server_config
from server.app.web import make_plugin_app,make_public_app
from client.app.runtime import client_config

FRPS=os.environ.get('FRPS_BIN') or shutil.which('frps')
FRPC=os.environ.get('FRPC_BIN') or shutil.which('frpc')
pytestmark=pytest.mark.skipif(not FRPS or not FRPC,reason='Requires Linux FRP binaries; run tools/Dockerfile.test')


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


async def wait_http(session,url,host,expected,timeout=30):
    deadline=asyncio.get_running_loop().time()+timeout
    while asyncio.get_running_loop().time()<deadline:
        try:
            async with session.get(url,headers={'Host':host}) as response:
                if response.status==200 and await response.text()==expected:
                    return
        except (ClientError,TimeoutError):
            pass
        await asyncio.sleep(.25)
    pytest.fail('Expected proxy did not become reachable')


@pytest.fixture
async def environment(tmp_path):
    async with AsyncExitStack() as stack:
        store=Store(tmp_path/'state.db','example.org')
        plugin_port=unused_port()
        authority=Authority(tmp_path/'identity.key',f'http://127.0.0.1:{plugin_port}')
        plugin=await stack.enter_async_context(TestServer(make_plugin_app(store,authority),port=plugin_port))
        pki=ensure_pki(tmp_path/'pki','tunnel.example.org')
        # Simulate only the trusted NPM hop inside network-none. OAuth uses the
        # real public handler; public HTTPS/NPM itself remains a deployment gate.
        @web.middleware
        async def trusted_npm(request,handler):
            response=await handler(request.clone(headers={**request.headers,
                'X-Forwarded-Proto':'https','X-Real-IP':'127.0.0.1'}))
            if response.status==200 and request.path=='/v1/token':
                authority.token_calls+=1
                if authority.short_tokens:
                    data=json.loads(response.body)
                    data['expires_in']=8
                    response.body=json.dumps(data).encode()
            return response
        authority.token_calls=0
        authority.short_tokens=False
        api=make_public_app(store,authority,{'trusted_proxy_ips':['127.0.0.1']})
        api.middlewares.insert(0,trusted_npm)
        token_server=await stack.enter_async_context(TestServer(api))
        port,http_port=unused_port(),unused_port()
        server=ServerRuntime(FRPS,tmp_path/'frps.json',store)
        await server.start(server_config(pki,port,http_port,plugin_port,bind='127.0.0.1'))
        stack.push_async_callback(server.stop)
        # OIDC discovery happens during frps startup. Establish a positive control
        # before deliberately stopping the policy/discovery service in an attack.
        deadline=asyncio.get_running_loop().time()+15
        while True:
            try:
                _,writer=await asyncio.open_connection('127.0.0.1',http_port)
                writer.close()
                await writer.wait_closed()
                break
            except OSError:
                if asyncio.get_running_loop().time()>=deadline:
                    pytest.fail('frps did not open its HTTP listener')
                await asyncio.sleep(.1)
        clients=[]
        for name in ('alpha','bravo'):
            creds=store.redeem(store.issue(name,int(time.time())).code,int(time.time()))
            app=web.Application()
            async def hello(request,identity=name): return web.Response(text=identity)
            async def websocket(request):
                ws=web.WebSocketResponse()
                await ws.prepare(request)
                async for message in ws:
                    if message.type==WSMsgType.TEXT: await ws.send_str(message.data)
                return ws
            app.router.add_get('/',hello)
            app.router.add_get('/ws',websocket)
            target=await stack.enter_async_context(TestServer(app))
            config=client_config({'client_id':creds.client_id,'secret':creds.secret,'domain':creds.domain,
                'tunnel_host':'tunnel.example.org','server_url':'https://tunnel.example.org','tunnel_port':port},pki.ca)
            config['serverAddr']='127.0.0.1'
            config['proxies'][0]['localPort']=target.port
            config['auth']['oidc']['tokenEndpointURL']=str(token_server.make_url('/v1/token'))
            runtime=FrpRuntime(FRPC,tmp_path/(name+'.json'))
            stack.push_async_callback(runtime.stop)
            clients.append((creds,runtime,config))
        session=await stack.enter_async_context(ClientSession(timeout=ClientTimeout(total=4)))
        yield store,authority,server,plugin,pki,clients,session,f'http://127.0.0.1:{http_port}',port


async def test_real_http_websocket_isolation_and_revoke(environment):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    for creds,runtime,config in clients:
        await runtime.start(config)
        await wait_http(session,url,creds.domain,creds.domain.split('.')[0])
    a,b=clients
    async with session.get(url,headers={'Host':'unknown.example.org'}) as response:
        assert response.status!=200
    ws=await session.ws_connect(url+'/ws',headers={'Host':a[0].domain})
    await ws.send_str('hello')
    assert (await ws.receive(timeout=5)).data=='hello'
    await server.revoke_and_disconnect(a[0].client_id)
    result=await ws.receive(timeout=10)
    assert result.type in (WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR)
    await ws.close()
    await wait_http(session,url,b[0].domain,'bravo')
    async with session.get(url,headers={'Host':a[0].domain}) as response:
        assert response.status!=200
    assert store.active(a[0].client_id) is None


async def test_real_native_oidc_refresh_after_token_expiry(environment):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    issue=authority.issue
    authority.short_tokens=True
    authority.issue=lambda client_id,**kwargs:issue(client_id,now=int(time.time())-3592,**kwargs)
    creds,runtime,config=clients[0]
    config['transport']['heartbeatInterval']=2
    config['transport']['heartbeatTimeout']=6
    await runtime.start(config)
    await wait_http(session,url,creds.domain,'alpha')
    previous=authority.token_calls
    await asyncio.sleep(10)
    await wait_http(session,url,creds.domain,'alpha')
    assert authority.token_calls>previous
    assert store.access_snapshot(creds.client_id,store.now())['last_seen'] is not None


@pytest.mark.parametrize('attack',['foreign_domain','wrong_name','wrong_ca','plaintext','policy_down'])
async def test_real_frp_rejects_invalid_connections(environment,attack,tmp_path):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    creds,runtime,config=clients[0]
    if attack=='foreign_domain': config['proxies'][0]['customDomains']=[clients[1][0].domain]
    if attack=='wrong_name': config['transport']['tls']['serverName']='other.example.org'
    if attack=='wrong_ca': config['transport']['tls']['trustedCaFile']=str(ensure_pki(tmp_path/'other','tunnel.example.org').ca)
    if attack=='plaintext': config['transport']['tls']={'enable':False}
    if attack=='policy_down': await plugin.close()
    config['loginFailExit']=True
    await runtime.start(config)
    await asyncio.sleep(3)
    for host in (creds.domain,clients[1][0].domain):
        async with session.get(url,headers={'Host':host}) as response:
            assert response.status!=200
