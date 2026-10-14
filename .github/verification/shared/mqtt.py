"""Optional bounded MQTTv5 delivery; broker publishers have no admin authority."""
import asyncio
import hashlib
import json
import secrets
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt

from shared.discovery import namespace, discovery_payloads, state_payload
from shared.files import atomic_write
from shared.mqtt_outbox import MqttOutbox

ACK_TIMEOUT=30
CONNECT_TIMEOUT=60
STOP_TIMEOUT=2
MANIFEST_COUNT=10000
MANIFEST_BYTES=1024*1024


def fingerprint(payload): return hashlib.sha256(payload.encode()).digest()


class MqttBridge:
    def __init__(self,instance_id,role,service_provider,state_provider,command_handler=None,*,discovery_cache=None):
        self.instance_id,self.role=instance_id,role
        self.prefix=namespace(instance_id,role)
        self.service_provider,self.state_provider,self.command_handler=service_provider,state_provider,command_handler
        self.session_nonce=secrets.token_hex(16)
        self.client=None
        self.connected=False
        self.queue=asyncio.Queue(maxsize=1)
        self.configs={}
        self.discovery_cache=Path(discovery_cache) if discovery_cache else None
        self.state='starting'
        self.task=None
        self.loop=None
        self.next_retry=0
        self.outbox=MqttOutbox()
        self._cursor=0
        self._cache_error=False
        self._closed=False
        self._network=None
        self._stop=threading.Event()
        self._publish_failed=threading.Event()
        self._handoff_lock=threading.Lock()
        self._handoff_pending=False
        self._events={}
        if self.discovery_cache and self.discovery_cache.exists():
            try:
                with self.discovery_cache.open('rb') as stream:
                    raw=stream.read(MANIFEST_BYTES+1)
                if len(raw)>MANIFEST_BYTES: raise ValueError()
                saved=json.loads(raw)
                if not isinstance(saved,list) or len(saved)>MANIFEST_COUNT: raise ValueError()
                uid='ha_tunnel_'+instance_id+'_'+role+'_'
                for topic in saved:
                    if not isinstance(topic,str) or not topic.startswith('homeassistant/') or '/'+uid not in topic or not topic.endswith('/config'): raise ValueError()
                if len(set(saved))!=len(saved): raise ValueError()
                self.configs={topic:b'' for topic in saved}
            except (ValueError,OSError,RecursionError):
                self._cache_error=True; self.state='discovery_cache_error'
        if not self._cache_error:
            try: self._reserve(self.state_provider(),legacy=bool(self.discovery_cache))
            except Exception: self.state='discovery_cache_error'; self._cache_error=True

    def status(self):
        return {'state':self.state,'pending':self.outbox.pending,
                'pending_bytes':self.outbox.bytes,'oldest_ack_age_s':self.outbox.oldest_age}

    def _save(self,topics):
        raw=json.dumps(sorted(topics),separators=(',',':')).encode()
        if len(topics)>MANIFEST_COUNT or len(raw)>MANIFEST_BYTES: raise ValueError('Discovery manifest full')
        if self.discovery_cache: atomic_write(self.discovery_cache,raw)

    def _reserve(self,states,legacy=False):
        topics=set(self.configs)
        size=len(json.dumps(sorted(topics),separators=(',',':')).encode())
        present=set()
        full=False
        for state in states:
            candidates=list(discovery_payloads(self.instance_id,self.role,state))
            if legacy and self.role=='server':
                uid=f'ha_tunnel_{self.instance_id}_{self.role}_{state["client_id"]}'
                candidates.extend(f'homeassistant/button/{uid}/{action}/config' for action in ('start','pause'))
            for topic in candidates:
                if topic in topics:
                    present.add(topic); continue
                extra=len(json.dumps(topic).encode())+(1 if topics else 0)
                if len(topics)>=MANIFEST_COUNT or size+extra>MANIFEST_BYTES:
                    full=True; continue
                topics.add(topic); present.add(topic); size+=extra
        if topics!=set(self.configs) or (self.discovery_cache and not self.discovery_cache.exists()):
            self._save(topics)  # Reservation precedes every possible publish.
            for topic in topics: self.configs.setdefault(topic,b'')
        return present,full

    def _enqueue(self,event):
        # Only connection state, birth, and failure signals cross the thread
        # boundary. One scheduled callback + one asyncio wakeup, even in storms.
        with self._handoff_lock:
            if self._closed or not self.loop or self.loop.is_closed(): return
            self._events[event[0]]=event
            if self._handoff_pending: return
            self._handoff_pending=True
        try: self.loop.call_soon_threadsafe(self._wake)
        except RuntimeError:
            with self._handoff_lock: self._handoff_pending=False

    def _wake(self):
        # Keep the latch until consumption, not merely until this callback ran.
        try: self.queue.put_nowait(('wake',))
        except asyncio.QueueFull: pass

    def _on_connect(self,client,userdata,flags,reason,properties):
        if client is self.client: self._enqueue(('connection',client,not reason.is_failure))

    def _on_disconnect(self,client,userdata,flags,reason,properties):
        if client is self.client: self._enqueue(('connection',client,False))

    def _on_publish(self,client,userdata,mid,reason,properties):
        # Success is polled on MQTTMessageInfo, which also handles early ACKs.
        # A negative MQTT5 PUBACK invalidates this whole connection.
        if client is self.client and reason.is_failure:
            self._publish_failed.set()
            self._enqueue(('failure',client))

    def _on_message(self,client,userdata,message):
        if client is self.client and message.topic=='homeassistant/status' and message.payload==b'online':
            self._enqueue(('birth',client))

    async def start(self):
        self.loop=asyncio.get_running_loop()
        self._closed=False
        await self._setup()
        self.task=asyncio.create_task(self._loop())

    async def _setup(self):
        if self._closed: return
        if self._network and self._network.is_alive():
            self.state='stopping'; self.next_retry=time.monotonic()+5; return
        try:
            async with asyncio.timeout(10): service=await self.service_provider()
            if self._closed: return
            if service is None:
                self.state='not_configured'; self.next_retry=time.monotonic()+30; return
            client=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id='hat-'+self.instance_id+'-'+self.role,
                protocol=mqtt.MQTTv5,reconnect_on_failure=False)
            client.max_queued_messages_set(256)
            client.max_inflight_messages_set(20)
            client.connect_timeout=5
            client.username_pw_set(service.username,service.password)
            if service.ssl: client.tls_set()
            client.will_set(self.prefix+'/availability','offline',qos=1,retain=True)
            client.on_connect=self._on_connect; client.on_disconnect=self._on_disconnect
            client.on_message=self._on_message; client.on_publish=self._on_publish
            self.client=client; self.outbox.bind(client)
            self._publish_failed.clear()
            self._stop=stop=threading.Event()
            def network():
                try:
                    client.connect(service.host,service.port,keepalive=30,clean_start=True)
                    # A late DNS/connect completion after close must never start
                    # a revived MQTT loop or replay queued messages.
                    if not stop.is_set(): client.loop_forever(timeout=.5,retry_first_connection=False)
                except Exception:
                    self._enqueue(('connection',client,False))
                finally:
                    client.disconnect()
                    self._enqueue(('connection',client,False))
            self._network=threading.Thread(target=network,name='ha-tunnel-mqtt',daemon=True)
            self.state='connecting'; self.next_retry=time.monotonic()+CONNECT_TIMEOUT
            self._network.start()
        except Exception as error:
            if getattr(self,'diagnostics',None): self.diagnostics.failure('service_error',error,component='mqtt',fatal=False)
            self.state='service_error'; self.next_retry=time.monotonic()+30

    async def handle_command(self,topic,payload,retained):
        # MQTT publishers cannot attest an authenticated HA administrator.
        return

    def _messages(self,states,present):
        yield self.prefix+'/availability','online',True
        for state in states:
            cid=state['client_id']
            for topic,config in discovery_payloads(self.instance_id,self.role,state).items():
                if topic not in present: continue
                raw=json.dumps(config,separators=(',',':'),sort_keys=True)
                # An older ACK digest cannot override queued/inflight intent:
                # replace a superseded tombstone with the current positive config.
                if self.configs[topic]!=fingerprint(raw) or topic in self.outbox.desired or topic in self.outbox.sent:
                    yield topic,raw,True
            yield f'{self.prefix}/{cid}/state',json.dumps(state_payload(state),separators=(',',':')),False
            if self.role=='server':
                yield f'{self.prefix}/{cid}/controls','online' if state.get('editable') and not state.get('revoked') else 'offline',True
        for topic in sorted(self.configs.keys()-present): yield topic,'',True

    def _acknowledge(self,present):
        acknowledgements=self.outbox.acknowledgements()
        # Paho marks MessageInfo published even for a negative MQTT5 PUBACK,
        # but only AFTER invoking on_publish. Read the latch after polling
        # infos so a callback racing this pass cannot authorize a tombstone.
        if self._publish_failed.is_set(): raise ValueError('MQTT PUBACK rejected')
        removed={message.topic for message in acknowledgements if message.payload=='' and message.topic not in present and message.topic in self.configs}
        if removed:
            self._save(self.configs.keys()-removed)
            for topic in removed: self.configs.pop(topic,None)
        for message in acknowledgements:
            if message.topic in self.configs:
                # A returned topic keeps its durable identity, but an ACKed
                # tombstone means the broker no longer retains its old config.
                self.configs[message.topic]=fingerprint(message.payload) if message.payload else b''

    async def reconcile(self,force=False):
        if not self.connected or self.client is None: return
        if self._cache_error:
            self.state='discovery_cache_error'; return
        try:
            if self.outbox.client is not self.client:
                self.outbox.bind(self.client)
                for topic in self.configs: self.configs[topic]=b''
            if self.outbox.oldest_age>=ACK_TIMEOUT:
                await self._reset('ack_timeout'); return
            states=self.state_provider()
            present,full=self._reserve(states)
            self._acknowledge(present)
            if force:
                for topic in self.configs: self.configs[topic]=b''
            # Keep only current unsent messages. Sent payloads remain charged
            # against both budgets until ACK or entire connection retirement.
            live=set(present)|set(self.configs)|{self.prefix+'/availability'}
            for state in states:
                live.update((f'{self.prefix}/{state["client_id"]}/state',f'{self.prefix}/{state["client_id"]}/controls'))
            self.outbox.discard_except(live)
            cursor=self._cursor
            first_rejected=None
            # Two streaming passes rotate admission without a second unbounded
            # payload dictionary. Existing queued topics always get refreshed.
            for suffix in (True,False):
                for index,(topic,payload,retain) in enumerate(self._messages(states,present)):
                    if (index>=cursor)!=suffix: continue
                    if not self.outbox.offer(topic,payload,retain) and first_rejected is None: first_rejected=index
            self._cursor=first_rejected if first_rejected is not None else 0
            self.outbox.drain()
            self._acknowledge(present)
            self.state='discovery_manifest_full' if full else 'backpressure' if first_rejected is not None else 'connected'
        except Exception as error:
            if getattr(self,'diagnostics',None): self.diagnostics.failure('service_error',error,component='mqtt',fatal=False)
            self.state='publish_error'

    async def _reset(self,reason):
        client=self.client
        self.client=None; self.connected=False
        self._stop.set()
        self.outbox.bind(None)
        if client: client.disconnect()
        deadline=time.monotonic()+STOP_TIMEOUT
        while self._network and self._network.is_alive() and time.monotonic()<deadline:
            await asyncio.sleep(.01)
        # Never join DNS in the default executor (it would block process exit),
        # and never create a second worker while a quarantined daemon is alive.
        self.state=reason; self.next_retry=time.monotonic()+1

    async def _loop(self):
        while True:
            try: await asyncio.wait_for(self.queue.get(),.5)
            except asyncio.TimeoutError: pass
            with self._handoff_lock:
                events=self._events; self._events={}; self._handoff_pending=False
            force=False
            for event in events.values():
                if event[1] is not self.client: continue
                if event[0]=='connection':
                    self.connected=event[2]
                    if self.connected:
                        self.client.subscribe('homeassistant/status',qos=1); force=True
                    else: await self._reset('offline')
                elif event[0]=='failure': await self._reset('publish_error')
                elif event[0]=='birth': force=True
            await self.reconcile(force=force)
            if not self.connected and time.monotonic()>=self.next_retry:
                if self.client: await self._reset('connect_timeout')
                await self._setup()

    async def close(self):
        self._closed=True
        if self.task:
            self.task.cancel(); await asyncio.gather(self.task,return_exceptions=True)
        if self.client and self.connected:
            try:
                info=self.client.publish(self.prefix+'/availability','offline',qos=1,retain=True)
                deadline=time.monotonic()+STOP_TIMEOUT
                while info.rc==0 and not info.is_published() and time.monotonic()<deadline: await asyncio.sleep(.01)
            except Exception: pass
        await self._reset('offline')
