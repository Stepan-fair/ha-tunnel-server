"""Real old FRP pools cannot access migrated identities; fresh credentials and new TLS work."""
import time
from urllib.parse import urlsplit
import pytest
from aiohttp import WSMsgType
from test_frp import environment,FRPS,FRPC,wait_http
from server.app.relay import ClientRelay
from server.app.access import AccessService
from server.app.domain_migration import DomainMigration
from server.app.setup import SetupService
from server.app.pki import ensure_pki
from tests.test_domain_migration import Supervisor,ready

pytestmark=pytest.mark.skipif(not FRPS or not FRPC,reason='Requires real Linux FRP binaries')

async def test_real_domain_cutover_requires_new_credentials_and_hostname(environment,tmp_path):
    store,authority,server,plugin,pki,clients,session,upstream,port=environment
    relay=ClientRelay(store,store.now,upstream_port=urlsplit(upstream).port)
    await relay.start(port=0);old_url=f'http://127.0.0.1:{relay.port}'
    access=AccessService(store,relay,store.now);server.access=access
    old=dict(base_domain='example.org',server_url='https://tunnel.example.org',npm_host='npm',
        admin_user_ids=['admin'],reserved_names=[],bandwidth_limit_mb=10)
    setup=SetupService(tmp_path,Supervisor(old));setup.options=old
    migration=DomainMigration(store,setup,access,readiness=ready)
    draft={**old,'base_domain':'example.net','server_url':'https://tunnel.example.net'}
    a=clients[0]
    try:
        a[2]['transport']['poolCount']=5
        await a[1].start(a[2]);await wait_http(session,old_url,a[0].domain,'alpha')
        ws=await session.ws_connect(old_url+'/ws',headers={'Host':a[0].domain})
        preview=await migration.preview(draft)
        await migration.apply(draft,'cutover',preview['revision'])
        assert (await ws.receive(timeout=3)).type in (WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR)
        await ws.close()
        assert a[1].status()['running']
        await migration.recover()
        relay.closing=False  # Simulate the fresh relay instance after app reload.
        await relay.start(port=0);new_url=f'http://127.0.0.1:{relay.port}'
        fresh=await access.redeem(store.reissue(a[0].client_id,int(time.time())).code)
        async with session.get(new_url,headers={'Host':fresh.domain}) as response:
            assert response.status!=200,'Old authenticated pools reached migrated identity'
        newer=ensure_pki(pki.ca.parent,'tunnel.example.net')
        await server.restart()
        a[2]['auth']['oidc']['clientSecret']=fresh.secret
        a[2]['transport']['tls']['serverName']='tunnel.example.net'
        a[2]['proxies'][0]['customDomains']=[fresh.domain]
        await a[1].stop();await a[1].start(a[2])
        await wait_http(session,new_url,fresh.domain,'alpha')
        async with session.get(new_url,headers={'Host':a[0].domain}) as response:assert response.status==404
    finally:await relay.close()
