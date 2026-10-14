"""Probe the HA WebSocket greeting through the permitted loopback relay."""
import asyncio
import json
import time
from aiohttp import ClientSession, ClientTimeout, WSMsgType, TraceConfig
from server.app.journal import Journal


class TelemetryService:
    def __init__(self, store, relay, clock):
        self.store,self.relay,self.clock=store,relay,clock
        self.results={}
        self.semaphore=asyncio.Semaphore(8)
        self.task=None
        self.probes=set()
        self.error=None
        self._probing=set()
        self._errors=set()
        self._scan_error=False

    def now(self): return self.clock.now() if hasattr(self.clock,'now') else self.clock()

    def snapshot(self, client_id):
        now=self.now()
        client=self.store.access_snapshot(client_id,now)
        result=self.results.get(client_id)
        allowed=client['access_state']=='allowed'
        epoch=self.store.admission.epoch(client_id,client['generation'])
        seen=client['last_seen']
        frp=allowed and epoch is not None and seen is not None and 0<=now-seen<=45
        fresh=result is not None and epoch is not None and result.get('owner_epoch')==self.store.admission.proof(client_id,client['generation']) and result['revision']==client['revision'] and result['generation']==client['generation'] and 0<=now-result['sampled_at']<=45
        ha=(bool(frp and result['ok']) if fresh else None) if allowed and epoch is not None else False
        rates=self.relay.rates(client_id)
        counts=(client['to_client_bytes'],client['from_client_bytes'])
        return {'frp_connected':frp,'ha_available':ha,'rtt_ms':result['rtt_ms'] if ha else None,
            'last_ha_success':result.get('last_success') if result else None,'last_frp_seen':seen,
            'sampled_at':result['sampled_at'] if result else None,'telemetry_age_s':max(0,now-result['sampled_at']) if result else None,
            'to_client_bps':rates[0] if rates is not None and allowed else None,
            'from_client_bps':rates[1] if rates is not None and allowed else None,
            'to_client_bytes':counts[0],'from_client_bytes':counts[1],'total_bytes':sum(counts),
            'traffic_started_at':client['traffic_started_at'],'telemetry_error':self.relay.telemetry_error or ('probe_error' if self._scan_error or client_id in self._errors or ha is None else None)}

    async def _probe(self, domain):
        start=time.monotonic()
        trace=TraceConfig()
        async def reject_redirect(*args): raise ValueError('HA probe redirect is forbidden')
        trace.on_request_redirect.append(reject_redirect)
        async with asyncio.timeout(5):
            async with ClientSession(timeout=ClientTimeout(total=5),trust_env=False,trace_configs=[trace]) as session:
                async with session.ws_connect(f'http://127.0.0.1:{self.relay.port}/api/websocket',
                        headers={'Host':domain},max_msg_size=8192,autoping=False) as ws:
                    msg=await ws.receive()
                    if msg.type!=WSMsgType.TEXT or len(msg.data.encode())>8192: raise ValueError('Invalid HA greeting')
                    data=json.loads(msg.data)
                    if not isinstance(data,dict) or data.get('type')!='auth_required' or not isinstance(data.get('ha_version'),str) or not 1<=len(data['ha_version'])<=64:
                        raise ValueError('Unexpected HA greeting')
                    return (time.monotonic()-start)*1000

    async def probe_once(self, client_id):
        if client_id in self._probing: return
        self._probing.add(client_id)
        try:
            async with self.semaphore:
                before=self.store.access_snapshot(client_id,self.now())
                epoch=self.store.admission.proof(client_id,before['generation'])
                if before['access_state']!='allowed' or epoch is None: return
                try: rtt=await self._probe(before['domain'])
                except Exception: rtt=None
                after=self.store.access_snapshot(client_id,self.now())
                if (before['revision'],before['generation'])!=(after['revision'],after['generation']) or after['access_state']!='allowed' or self.store.admission.proof(client_id,after['generation'])!=epoch: return
                previous=self.results.get(client_id,{})
                self.results[client_id]={'ok':rtt is not None,'rtt_ms':rtt,'sampled_at':self.now(),
                    'revision':after['revision'],'generation':after['generation'],'owner_epoch':epoch,
                    'last_success':self.now() if rtt is not None else previous.get('last_success')}
        finally:
            self._probing.discard(client_id)

    async def start(self): self.task=asyncio.create_task(self._loop())

    async def _loop(self):
        queue=asyncio.Queue()
        scheduled=set()
        current=set()
        due={}

        async def worker():
            while True:
                cid=await queue.get()
                if cid not in current:
                    scheduled.discard(cid)
                    continue
                try:
                    # Requeue in completion order: a slow tail never holds up
                    # the next fair pass. Eight workers, one visit per HA.
                    await asyncio.sleep(max(0,due.get(cid,0)-time.monotonic()))
                    if cid not in current: continue
                    due[cid]=time.monotonic()+15
                    await self.probe_once(cid)
                    snap=self.snapshot(cid)
                    for key in ('frp_connected','ha_available'):
                        if snap[key] is not None:
                            Journal(self.store).transition(cid,key,snap[key],self.now())
                    self._errors.discard(cid)
                    if not self._errors and not self._scan_error: self.error=None
                except Exception as error:
                    self.results.pop(cid,None)
                    self._errors.add(cid)
                    self.error='probe_error'
                    if getattr(self,'diagnostics',None): self.diagnostics.failure('storage_error',error,component='telemetry',fatal=False)
                finally:
                    if cid in current: queue.put_nowait(cid)
                    else: scheduled.discard(cid)

        tasks=[asyncio.create_task(worker()) for _ in range(8)]
        self.probes.update(tasks)
        try:
            while True:
                try:
                    clients=self.store.list_clients()
                    self._scan_error=False
                    current={c['client_id'] for c in clients}
                    for cache in (self.results,due):
                        for cid in cache.keys()-current: cache.pop(cid,None)
                    self._errors.intersection_update(current)
                    for client in clients:
                        cid=client['client_id']
                        if cid not in scheduled:
                            scheduled.add(cid); queue.put_nowait(cid)
                except Exception as error:
                    self.results.clear()
                    self._scan_error=True
                    self.error='probe_error'
                    if getattr(self,'diagnostics',None): self.diagnostics.failure('storage_error',error,component='telemetry',fatal=False)
                await asyncio.sleep(1)
        finally:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
            self.probes.difference_update(tasks)

    async def close(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task,return_exceptions=True)
