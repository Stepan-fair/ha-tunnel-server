import asyncio
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from server.app.store import Store
from server.app.relay import ClientRelay
from server.app.telemetry import TelemetryService
from shared.telemetry import parse_telemetry, age_telemetry


@pytest.mark.parametrize('greeting,expected', [
    ({'type':'auth_required','ha_version':'2026.9.4'},True),
    ({'type':'auth_ok','ha_version':'2026.9.4'},False),
    ({'type':'auth_required'},False),
    ({'type':'auth_required','ha_version':'x'*9000},False),
])
async def test_probe_accepts_only_ha_auth_required(tmp_path,greeting,expected):
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    c=store.redeem(store.issue('alpha',1000).code,1001)
    store.seen(c.client_id,2000)
    store.live_proxies={c.client_id:0}
    app=web.Application()
    async def ws(request):
        assert request.host==c.domain
        response=web.WebSocketResponse()
        await response.prepare(request)
        await response.send_json(greeting)
        async for _ in response: pass
        return response
    app.router.add_get('/api/websocket',ws)
    async with TestServer(app) as upstream:
        relay=ClientRelay(store,store.clock,upstream_port=upstream.port)
        await relay.start(port=0)
        telemetry=TelemetryService(store,relay,store.clock)
        try:
            await telemetry.probe_once(c.client_id)
            snap=telemetry.snapshot(c.client_id)
            assert snap['ha_available'] is expected
            assert (snap['rtt_ms'] is not None) is expected
            parsed=parse_telemetry(snap,100)
            assert age_telemetry(parsed,146)['ha_available'] is None
            store.clock=lambda:2046
            telemetry.clock=store.clock
            assert not telemetry.snapshot(c.client_id)['frp_connected']
        finally:
            await telemetry.close(); await relay.close()


async def test_probe_result_discarded_after_revision_change(tmp_path,monkeypatch):
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    c=store.redeem(store.issue('alpha',1000).code,1001)
    store.set_capabilities(c.client_id,['access-v1'])
    store.seen(c.client_id,2000); store.live_proxies={c.client_id:0}
    relay=ClientRelay(store,store.clock)
    service=TelemetryService(store,relay,store.clock)
    entered,released=asyncio.Event(),asyncio.Event()
    async def probe(domain):
        entered.set(); await released.wait(); return 12.0
    monkeypatch.setattr(service,'_probe',probe)
    task=asyncio.create_task(service.probe_once(c.client_id))
    await entered.wait()
    store.apply_access(c.client_id,'pause','pause',0,2000)
    released.set(); await task
    assert service.snapshot(c.client_id)['ha_available'] is False
    assert service.snapshot(c.client_id)['rtt_ms'] is None
    await service.close()


async def test_probe_redirect_is_not_followed(tmp_path):
    store=Store(tmp_path/'state.db','example.org')
    relay=ClientRelay(store,store.now)
    visits=[]
    app=web.Application()
    async def redirect(request): raise web.HTTPFound('/other')
    async def other(request): visits.append(True); return web.Response(text='unexpected')
    app.router.add_get('/api/websocket',redirect); app.router.add_get('/other',other)
    async with TestServer(app) as upstream:
        relay.port=upstream.port
        service=TelemetryService(store,relay,store.now)
        with pytest.raises(ValueError): await service._probe('alpha.example.org')
        assert visits==[]
