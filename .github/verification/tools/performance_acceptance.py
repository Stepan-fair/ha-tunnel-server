"""Bounded isolated measurements; run separately against each source tree.

Synthetic identities, real loopback HTTP/WebSocket and MQTT packets. Never point
this at an installed HA. The caller chooses a frozen *local source tree*, not a
network target. RSS is the process working set (peak on POSIX).
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import threading
import time
from types import SimpleNamespace


def rss_bytes():
    if os.name=='nt':
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)]+[(n,ctypes.c_size_t) for n in (
                'PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
                'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
        counters=Counters();counters.cb=ctypes.sizeof(counters)
        handle=ctypes.windll.kernel32.GetCurrentProcess
        handle.restype=wintypes.HANDLE
        query=ctypes.windll.psapi.GetProcessMemoryInfo
        query.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
        query.restype=wintypes.BOOL
        if not query(handle(),ctypes.byref(counters),counters.cb): raise OSError('RSS unavailable')
        return counters.WorkingSetSize
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024


def source_digest(source):
    digest=hashlib.sha256()
    for directory in ('server/app','client/app','shared'):
        for path in sorted((source/directory).rglob('*.py')):
            digest.update(path.relative_to(source).as_posix().encode()+b'\0'+path.read_bytes())
    return digest.hexdigest()


async def mqtt_measurement(root):
    from shared.mqtt import MqttBridge
    from shared.supervisor_services import MqttService
    helpers=runpy.run_path(str(root/'tests/test_mqtt_outbox.py'))
    wire=await helpers['WireBroker']().start()
    async def service(): return MqttService('127.0.0.1',wire.port,'synthetic','synthetic',False)
    bridge=MqttBridge('a'*32,'server',service,lambda:[helpers['state']()])
    started=time.monotonic();cpu=time.process_time();before=rss_bytes();peak=before
    attempts=0; stopped=None
    try:
        await bridge.start();await helpers['until'](lambda:bridge.connected,5)
        for attempts in range(1,511):
            await bridge.reconcile(force=True)
            if attempts%10==0:
                await asyncio.sleep(.001);peak=max(peak,rss_bytes())
                if len(bridge.client._out_messages)>10000 or peak-before>64*1024*1024:
                    stopped='measurement_cap';break
        await asyncio.sleep(.1)
        queued=len(bridge.client._out_messages)
        pending=bridge.status().get('pending')
        # Observe actual loop handoffs from one bounded foreign-thread burst.
        loop=bridge.loop;handoffs=[0]
        def schedule(callback,*args):
            handoffs[0]+=1;return loop.call_soon_threadsafe(callback,*args)
        bridge.loop=SimpleNamespace(is_closed=loop.is_closed,call_soon_threadsafe=schedule)
        message=SimpleNamespace(topic='homeassistant/status',payload=b'online',retain=False)
        thread=threading.Thread(target=lambda:[bridge._on_message(bridge.client,None,message) for _ in range(10000)])
        burst=time.monotonic();thread.start();thread.join(2)
        if thread.is_alive(): raise RuntimeError('Callback burst did not finish')
        burst_ms=(time.monotonic()-burst)*1000
        peak=max(peak,rss_bytes());await asyncio.sleep(.05);bridge.loop=loop
        return dict(attempts=attempts,paho_queued=queued,wire_no_puback=len(wire.records),pending=pending,
            callback_count=10000,callback_handoffs=handoffs[0],callback_ms=round(burst_ms,3),
            rss_before=before,rss_peak=peak,cpu_s=round(time.process_time()-cpu,4),
            elapsed_s=round(time.monotonic()-started,4),stopped=stopped)
    finally:
        # Close the deliberately non-acknowledging peer before joining Paho.
        # Older Paho owners wait indefinitely for their pending disconnect otherwise.
        if bridge.task:
            bridge.task.cancel()
            await asyncio.gather(bridge.task,return_exceptions=True)
        for writer in wire.connections: writer.close()
        await asyncio.wait_for(wire.close(),5)
        await asyncio.wait_for(bridge.close(),8)


async def telemetry_measurement(directory):
    from aiohttp import web,encode_basic_auth
    from aiohttp.test_utils import TestServer,TestClient
    from server.app.store import Store
    from server.app.telemetry import TelemetryService
    from server.app.relay import ClientRelay
    from server.app.web import make_public_app
    from server.app.identity import Authority
    started=time.monotonic(); clock=lambda:2000+time.monotonic()-started
    store=Store(directory/'state.db','example.org',clock=clock)
    clients=[store.redeem(store.issue(f'c-{i}',1000).code,1001) for i in range(112)]
    for c in clients:
        if hasattr(store,'admission'):
            owner=store.admission.login(c.client_id,0,'','process')
            store.admission.activity(c.client_id,0,owner['run_id'],owner['epoch'],'Ping')
        elif hasattr(store,'live_proxies'):
            # The baseline records publication in this predecessor cache.
            store.live_proxies[c.client_id]=0
        store.seen(c.client_id,clock())
    relay=ClientRelay(store,clock);service=TelemetryService(store,relay,clock)
    active=0;maximum=0;visits=[];finished={};first_repeat=None
    async def greeting(request):
        nonlocal active,maximum,first_repeat
        name=request.headers['Host'];at=time.monotonic();visits.append((name,at))
        if name in finished and first_repeat is None: first_repeat=at
        active+=1;maximum=max(maximum,active)
        ws=web.WebSocketResponse();await ws.prepare(request)
        try:
            await asyncio.sleep(4)
            await ws.send_json({'type':'auth_required','ha_version':'synthetic'})
            finished.setdefault(name,time.monotonic());await ws.receive()
        except (ConnectionError,asyncio.CancelledError): pass
        finally: active-=1;await ws.close()
        return ws
    app=web.Application();app.router.add_get('/api/websocket',greeting)
    server=TestServer(app);await server.start_server();relay.port=server.port
    api=make_public_app(store,Authority(directory/'identity.key','http://127.0.0.1:19000'),
        {'trusted_proxy_ips':['127.0.0.1']},telemetry=service)
    async def heartbeat():
        while True:
            for client in clients:store.seen(client.client_id,clock())
            await asyncio.sleep(10)
    keepalive=asyncio.create_task(heartbeat());cpu=time.process_time();before=rss_bytes()
    sweep_start=time.monotonic();stale=None;latencies=[];codes=[]
    await service.start()
    try:
        async with TestClient(TestServer(api)) as http:
            # 112 different authenticated principals, same proxy/source IP.
            for client in clients*2:
                at=time.monotonic()
                response=await http.post('/v1/client/status',headers={'X-Forwarded-Proto':'https',
                    'X-Real-IP':'192.0.2.10','Authorization':encode_basic_auth(client.client_id,client.secret)},
                    json={'capabilities':['access-v1','telemetry-v1']})
                await response.read();codes.append(response.status);latencies.append((time.monotonic()-at)*1000)
        async with asyncio.timeout(85):
            while len(finished)<112 or first_repeat is None:
                if stale is None and time.monotonic()-sweep_start>=50:
                    first_domain=visits[0][0]
                    first_client=next(c for c in clients if c.domain==first_domain)
                    stale=service.snapshot(first_client.client_id)['ha_available'] is None
                await asyncio.sleep(.02)
        ordered=sorted(latencies)
        return dict(clients=112,delay_s=4,max_active=maximum,unique_first_sweep=len({n for n,_ in visits[:112]}),
            full_sweep_s=round(max(finished.values())-sweep_start,3),
            first_revisit_s=round(first_repeat-sweep_start,3),stale_null_at_50s=stale,
            status_requests=len(codes),status_200=codes.count(200),status_429=codes.count(429),status_p50_ms=round(ordered[len(ordered)//2],3),
            status_p95_ms=round(ordered[int(len(ordered)*.95)],3),status_max_ms=round(max(ordered),3),
            rss_before=before,rss_after=rss_bytes(),cpu_s=round(time.process_time()-cpu,3))
    finally:
        keepalive.cancel();await asyncio.gather(keepalive,return_exceptions=True)
        await service.close();await server.close()


async def run(source,root):
    with tempfile.TemporaryDirectory(prefix='ha-tunnel-measure-') as temporary:
        return {'source_sha256':source_digest(source),'python':sys.version.split()[0],
            'mqtt':await mqtt_measurement(root),'telemetry':await telemetry_measurement(Path(temporary))}


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,default=root)
    args=parser.parse_args();source=args.source.resolve(strict=True)
    sys.path.insert(0,str(source))
    print(json.dumps(asyncio.run(run(source,root)),sort_keys=True))
