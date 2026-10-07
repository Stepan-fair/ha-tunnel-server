"""Real FRP0.71 generation propagation and selected-client live stream isolation."""
import asyncio
import time
from urllib.parse import urlsplit
import pytest
from aiohttp import WSMsgType
from test_frp import environment, FRPS, FRPC, wait_http
from server.app.relay import ClientRelay
from server.app.access import AccessService
from client.app.runtime import client_config

pytestmark=pytest.mark.skipif(not FRPS or not FRPC,reason='Requires real Linux FRP binaries')


async def test_real_pause_survivor_resume_and_rebind_generation(environment):
    store,authority,server,plugin,pki,clients,session,upstream,port=environment
    relay=ClientRelay(store,store.now,upstream_port=urlsplit(upstream).port)
    await relay.start(port=0)
    access=AccessService(store,relay,store.now)
    server.access=access
    url=f'http://127.0.0.1:{relay.port}'
    try:
        for c,runtime,config in clients:
            store.set_capabilities(c.client_id,['access-v1','telemetry-v1'])
            await runtime.start(config)
            await wait_http(session,url,c.domain,c.domain.split('.')[0])
        a,b=clients
        wa=await session.ws_connect(url+'/ws',headers={'Host':a[0].domain})
        wb=await session.ws_connect(url+'/ws',headers={'Host':b[0].domain})
        try:
            await wa.send_str('alpha'); assert (await wa.receive(timeout=5)).data=='alpha'
            await wb.send_str('before'); assert (await wb.receive(timeout=5)).data=='before'
            await access.command(a[0].client_id,'pause','pause',0)
            assert (await wa.receive(timeout=3)).type in (WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR)
            await wb.send_str('same session'); assert (await wb.receive(timeout=3)).data=='same session'
            async with session.get(url,headers={'Host':a[0].domain}) as response: assert response.status==403
            await access.command(a[0].client_id,'start','start',1)
            await wait_http(session,url,a[0].domain,'alpha')
            # Replace credentials in the existing FRP config. Generation1 can only publish
            # if real frps carries the normalized Login metadata into NewProxy.
            newer=await access.redeem(store.reissue(a[0].client_id,int(time.time())).code)
            config=a[2]
            config['auth']['oidc']['clientSecret']=newer.secret
            await a[1].stop(); await a[1].start(config)
            await wait_http(session,url,newer.domain,'alpha')
            assert store.live_proxies[newer.client_id]==1
            await wb.send_str('after replacement'); assert (await wb.receive(timeout=3)).data=='after replacement'
            snap=store.access_snapshot(newer.client_id,store.now())
            await access.command(newer.client_id,'revoke','revoke',snap['revision'])
            await wb.send_str('after revoke'); assert (await wb.receive(timeout=3)).data=='after revoke'
        finally: await wa.close(); await wb.close()
    finally: await relay.close()


async def test_rebind_never_routes_through_old_preopened_pool(environment):
    store,authority,server,plugin,pki,clients,session,upstream,port=environment
    relay=ClientRelay(store,store.now,upstream_port=urlsplit(upstream).port)
    await relay.start(port=0)
    access=AccessService(store,relay,store.now)
    server.access=access
    url=f'http://127.0.0.1:{relay.port}'
    try:
        for c,runtime,config in clients:
            config['transport']['poolCount']=5
            store.set_capabilities(c.client_id,['access-v1','telemetry-v1'])
            await runtime.start(config)
            await wait_http(session,url,c.domain,c.domain.split('.')[0])
        a,b=clients
        await asyncio.sleep(.3)
        wa=await session.ws_connect(url+'/ws',headers={'Host':a[0].domain})
        wb=await session.ws_connect(url+'/ws',headers={'Host':b[0].domain})
        try:
            newer=await access.redeem(store.reissue(a[0].client_id,int(time.time())).code)
            assert (await wa.receive(timeout=3)).type in (WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR)
            # The old frpc and its valid cached JWT/pool remain running here.
            async with session.get(url,headers={'Host':newer.domain}) as response:
                assert response.status!=200, 'New generation was routed through the old FRP pool'
            await wb.send_str('survives rebind')
            assert (await wb.receive(timeout=3)).data=='survives rebind'
            assert a[1].status()['running']
        finally: await wa.close();await wb.close()
    finally: await relay.close()
