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

    def now(self): return self.clock.now() if hasattr(self.clock,'now') else self.clock()

    def snapshot(self, client_id):
        now=self.now()
        client=self.store.access_snapshot(client_id,now)
        result=self.results.get(client_id)
        allowed=client['access_state']=='allowed'
        published=getattr(self.store,'live_proxies',{}).get(client_id)==client['generation']
        seen=client['last_seen']
        frp=allowed and published and seen is not None and 0<=now-seen<=45
        fresh=result is not None and result['revision']==client['revision'] and result['generation']==client['generation'] and 0<=now-result['sampled_at']<=45
        ha=bool(frp and fresh and result['ok'])
        rates=self.relay.rates(client_id)
        counts=(client['to_client_bytes'],client['from_client_bytes'])
        return {'frp_connected':frp,'ha_available':ha,'rtt_ms':result['rtt_ms'] if ha else None,
            'last_ha_success':result.get('last_success') if result else None,'last_frp_seen':seen,
            'sampled_at':result['sampled_at'] if result else None,'telemetry_age_s':max(0,now-result['sampled_at']) if result else None,
            'to_client_bps':rates[0] if rates is not None and allowed else None,
            'from_client_bps':rates[1] if rates is not None and allowed else None,
            'to_client_bytes':counts[0],'from_client_bytes':counts[1],'total_bytes':sum(counts),
            'traffic_started_at':client['traffic_started_at'],'telemetry_error':self.error or self.relay.telemetry_error}

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
        async with self.semaphore:
            before=self.store.access_snapshot(client_id,self.now())
            if not self.snapshot(client_id)['frp_connected']: return
            try: rtt=await self._probe(before['domain'])
            except Exception: rtt=None
            after=self.store.access_snapshot(client_id,self.now())
            if (before['revision'],before['generation'])!=(after['revision'],after['generation']) or after['access_state']!='allowed': return
            previous=self.results.get(client_id,{})
            self.results[client_id]={'ok':rtt is not None,'rtt_ms':rtt,'sampled_at':self.now(),
                'revision':after['revision'],'generation':after['generation'],
                'last_success':self.now() if rtt is not None else previous.get('last_success')}

    async def start(self): self.task=asyncio.create_task(self._loop())

    async def _loop(self):
        while True:
            tasks=[]
            try:
                clients=self.store.list_clients()
                tasks=[asyncio.create_task(self.probe_once(c['client_id'])) for c in clients]
                self.probes.update(tasks)
                outcomes=await asyncio.gather(*tasks,return_exceptions=True)
                self.error=None
                for client,outcome in zip(clients,outcomes):
                    if isinstance(outcome,Exception):
                        self.results.pop(client['client_id'],None)
                        self.error='probe_storage_error'
                        if getattr(self,'diagnostics',None): self.diagnostics.failure('storage_error',outcome,component='telemetry',fatal=False)
                    else:
                        snap=self.snapshot(client['client_id'])
                        for key in ('frp_connected','ha_available'):
                            Journal(self.store).transition(client['client_id'],key,snap[key],self.now())
            except Exception as error:
                if getattr(self,'diagnostics',None): self.diagnostics.failure('storage_error',error,component='telemetry',fatal=False)
                self.results.clear()
                self.error='probe_storage_error'
            finally:
                self.probes.difference_update(tasks)
            await asyncio.sleep(15)

    async def close(self):
        tasks=tuple(self.probes)+((self.task,) if self.task else ())
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
