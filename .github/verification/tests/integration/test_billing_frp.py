"""Real FRP/HTTP/WSS paid expiry and same-session free-client isolation."""
import asyncio,time
from urllib.parse import urlsplit
import pytest
from aiohttp import WSMsgType
from test_frp import environment,FRPS,FRPC,wait_http
from server.app.relay import ClientRelay
from server.app.access import AccessService
from server.app.billing import BillingRepository

pytestmark=pytest.mark.skipif(not FRPS or not FRPC,reason='Requires real Linux FRP binaries')

async def test_paid_expiry_closes_streams_free_client_survives_and_topup_resumes(environment):
    store,authority,server,plugin,pki,clients,session,upstream,port=environment
    now=[time.time()];store.clock=lambda:now[0]
    relay=ClientRelay(store,store.now,upstream_port=urlsplit(upstream).port)
    await relay.start(port=0)
    access=AccessService(store,relay,store.now);server.access=access
    a,b=clients;cid=a[0].client_id;repo=BillingRepository(store)
    def pay(action,value,key):
        snap=store.access_snapshot(cid,now[0])
        return repo.command(cid,action,key,snap['revision'],value_kopecks=value,now=now[0],timezone='Europe/Moscow')
    pay('set_price',30000,'price');paid=pay('topup',30000,'paid')
    url=f'http://127.0.0.1:{relay.port}'
    try:
        for credentials,runtime,config in clients:
            store.set_capabilities(credentials.client_id,['access-v1','telemetry-v1'])
            config['transport']['poolCount']=5
            await runtime.start(config);await wait_http(session,url,credentials.domain,credentials.domain.split('.')[0])
        wa=await session.ws_connect(url+'/ws',headers={'Host':a[0].domain})
        wb=await session.ws_connect(url+'/ws',headers={'Host':b[0].domain})
        try:
            now[0]=paid['billing']['paid_until']
            await access.expire_once()
            assert (await wa.receive(timeout=3)).type in (WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR)
            await wb.send_str('free survives');assert (await wb.receive(timeout=3)).data=='free survives'
            async with session.get(url,headers={'Host':a[0].domain}) as response:assert response.status==403
            now[0]+=86400*5
            snap=store.access_snapshot(cid,now[0])
            resumed=await access.billing_command(cid,'topup','second',snap['revision'],value_kopecks=30000,timezone='Europe/Moscow')
            assert resumed['billing']['paid_from']==now[0]
            await wait_http(session,url,a[0].domain,'alpha')
            await wb.send_str('same free session');assert (await wb.receive(timeout=3)).data=='same free session'
        finally:await wa.close();await wb.close()
    finally:await relay.close()
