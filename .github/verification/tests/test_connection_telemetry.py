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


async def test_probe_loop_bounds_pending_tasks_and_visits_every_client(tmp_path,monkeypatch):
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    clients=[store.redeem(store.issue(f'client-{i}',1000).code,1001) for i in range(24)]
    store.live_proxies={c.client_id:0 for c in clients}
    for client in clients: store.seen(client.client_id,2000)
    relay=ClientRelay(store,store.clock)
    service=TelemetryService(store,relay,store.clock)
    entered,released,complete=asyncio.Event(),asyncio.Event(),asyncio.Event()
    visits=[]
    async def probe(domain):
        visits.append(domain)
        if len(visits)==8: entered.set()
        await released.wait()
        if len(visits)==len(clients): complete.set()
        return 12.0
    monkeypatch.setattr(service,'_probe',probe)
    await service.start()
    try:
        await asyncio.wait_for(entered.wait(),2)
        assert len(service.probes)<=8, 'Queued probes must not allocate one task per client'
        released.set()
        await asyncio.wait_for(complete.wait(),3)
        await asyncio.sleep(0)
        assert set(visits)=={c.domain for c in clients}
        assert all(service.snapshot(c.client_id)['ha_available'] for c in clients)
    finally:
        released.set()
        await service.close()


async def test_probe_shutdown_cancels_blocked_workers(tmp_path,monkeypatch):
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    clients=[store.redeem(store.issue(f'client-{i}',1000).code,1001) for i in range(16)]
    store.live_proxies={c.client_id:0 for c in clients}
    for client in clients: store.seen(client.client_id,2000)
    service=TelemetryService(store,ClientRelay(store,store.clock),store.clock)
    entered=asyncio.Event()
    visits=[]
    async def probe(domain):
        visits.append(domain)
        if len(visits)==8: entered.set()
        await asyncio.Future()
    monkeypatch.setattr(service,'_probe',probe)
    await service.start()
    try:
        await asyncio.wait_for(entered.wait(),2)
        workers=tuple(service.probes)
        assert len(workers)==8 and all(not task.done() for task in workers)
        await asyncio.wait_for(service.close(),1)
        assert all(task.cancelled() for task in workers)
        assert service.task.done()
    finally:
        await service.close()
