import asyncio
from types import SimpleNamespace

import pytest

from pathlib import Path
import runpy
from aiohttp import encode_basic_auth
from aiohttp.test_utils import TestClient, TestServer
from client.app.status import validate_status
from server.app.identity import Authority
from server.app.web import make_public_app
from server.app.relay import ClientRelay
from server.app.store import Store
from server.app.telemetry import TelemetryService
from shared.telemetry import parse_telemetry


def setup(tmp_path, count=1):
    now=[2000.0]
    store=Store(tmp_path/'db','example.org',clock=lambda:now[0])
    clients=[store.redeem(store.issue(f'c-{i}',1000).code,1001) for i in range(count)]
    for c in clients:
        owner=store.admission.login(c.client_id,0,'','process')
        store.admission.activity(c.client_id,0,owner['run_id'],owner['epoch'],'Ping')
        store.seen(c.client_id,2000)
    return now,store,clients,TelemetryService(store,ClientRelay(store,store.clock),store.clock)


async def test_stale_probe_is_unknown_but_fresh_negative_is_false(tmp_path,monkeypatch):
    now,store,(c,),service=setup(tmp_path)
    async def positive(domain): return 4.0
    monkeypatch.setattr(service,'_probe',positive)
    await service.probe_once(c.client_id)
    assert service.snapshot(c.client_id)['ha_available'] is True
    now[0]+=46
    store.seen(c.client_id,now[0])
    snap=service.snapshot(c.client_id)
    assert snap['frp_connected'] is True
    assert snap['ha_available'] is None and snap['rtt_ms'] is None
    assert snap['telemetry_error']=='probe_error'
    async def negative(domain): raise OSError('unreachable')
    monkeypatch.setattr(service,'_probe',negative)
    await service.probe_once(c.client_id)
    assert service.snapshot(c.client_id)['ha_available'] is False


async def test_server_worker_error_is_accepted_by_current_and_legacy_client(tmp_path,monkeypatch):
    _,store,(c,),service=setup(tmp_path)
    async def broken(cid): raise RuntimeError('storage unavailable')
    monkeypatch.setattr(service,'probe_once',broken)
    await service.start()
    try:
        for _ in range(100):
            if service.error: break
            await asyncio.sleep(.01)
        snap=service.snapshot(c.client_id)
        # Frozen telemetry-v1 wire enum used by 0.4.x; no new fields/reasons.
        assert snap['telemetry_error'] in (None,'traffic_storage_error','probe_error')
        assert snap['telemetry_error']=='probe_error'
        parsed=parse_telemetry(snap,0)
        legacy=runpy.run_path(str(Path(__file__).parent/'fixtures/telemetry_v1_043.py'))
        assert legacy['parse_telemetry'](snap,0)==parsed
        authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
        app=make_public_app(store,authority,{'trusted_proxy_ips':['127.0.0.1']},telemetry=service)
        async with TestClient(TestServer(app)) as http:
            response=await http.post('/v1/client/status',headers={'X-Forwarded-Proto':'https','Authorization':encode_basic_auth(c.client_id,c.secret)},
                json={'capabilities':['access-v1','telemetry-v1']})
            assert response.status==200
            status=validate_status(await response.json(),c.client_id)
        assert parsed['ha_available'] is None and status['telemetry']==snap
    finally: await service.close()


async def test_no_overlapping_probe_for_same_client(tmp_path,monkeypatch):
    _,_,(c,),service=setup(tmp_path)
    entered,release=asyncio.Event(),asyncio.Event()
    calls=[]
    async def probe(domain):
        calls.append(domain); entered.set(); await release.wait(); return 1.0
    monkeypatch.setattr(service,'_probe',probe)
    one=asyncio.create_task(service.probe_once(c.client_id))
    await entered.wait()
    two=asyncio.create_task(service.probe_once(c.client_id))
    await asyncio.sleep(0)
    release.set(); await asyncio.gather(one,two)
    assert calls==[c.domain]


async def test_112_slow_clients_are_fair_without_false_stale_or_batch_barrier(tmp_path,monkeypatch):
    now,store,clients,service=setup(tmp_path,112)
    monkeypatch.setattr('server.app.telemetry.time',SimpleNamespace(monotonic=lambda:now[0]))
    batches=asyncio.Queue()
    release=asyncio.Semaphore(0)
    visits=[]
    active=set()
    repeated=asyncio.Event()
    async def probe(domain):
        assert domain not in active
        active.add(domain); visits.append(domain)
        assert len(active)<=8
        await batches.put(domain)
        try:
            if len(visits)>112: repeated.set()
            await release.acquire()
            return 4000.0
        finally: active.remove(domain)
    monkeypatch.setattr(service,'_probe',probe)
    await service.start()
    try:
        for batch in range(14):
            for _ in range(8): await asyncio.wait_for(batches.get(),2)
            now[0]+=4
            if batch<13:
                for _ in range(8): release.release()
        # 112th remains slow: free one worker; first HA must be revisited.
        release.release()
        await asyncio.wait_for(repeated.wait(),2)
        assert set(visits[:112])=={c.domain for c in clients}
        first=next(c for c in clients if c.domain==visits[0])
        store.seen(first.client_id,now[0])
        snap=service.snapshot(first.client_id)
        assert snap['ha_available'] is None and snap['telemetry_error']=='probe_error'
        assert len(service.probes)==8
    finally: await service.close()

async def test_one_probe_storage_failure_does_not_mark_survivor_failed(tmp_path,monkeypatch):
    _,_,clients,service=setup(tmp_path,2)
    actual=service.probe_once
    async def positive(domain): return 3.0
    async def failing(cid):
        if cid==clients[0].client_id: raise RuntimeError('one client storage failed')
        await actual(cid)
    monkeypatch.setattr(service,'_probe',positive)
    monkeypatch.setattr(service,'probe_once',failing)
    await service.start()
    try:
        for _ in range(100):
            if service.results: break
            await asyncio.sleep(.01)
        assert service.snapshot(clients[0].client_id)['telemetry_error']=='probe_error'
        snap=service.snapshot(clients[1].client_id)
        assert snap['ha_available'] is True and snap['telemetry_error'] is None
    finally: await service.close()

async def test_stale_sample_stays_unknown_when_status_heartbeat_also_ages(tmp_path,monkeypatch):
    now,store,(c,),service=setup(tmp_path)
    async def positive(domain): return 1.0
    monkeypatch.setattr(service,'_probe',positive)
    await service.probe_once(c.client_id)
    now[0]+=46
    snap=service.snapshot(c.client_id)
    assert snap['frp_connected'] is False
    assert snap['ha_available'] is None and snap['telemetry_error']=='probe_error'
    store.revoke(c.client_id)
    assert service.snapshot(c.client_id)['ha_available'] is False
