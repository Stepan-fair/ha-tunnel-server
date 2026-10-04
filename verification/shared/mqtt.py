"""Optional MQTTv5 discovery; network callbacks never mutate application state."""
import asyncio
import json
import secrets
import time
from pathlib import Path
from shared.files import atomic_write
import paho.mqtt.client as mqtt
from shared.discovery import namespace,discovery_payloads,state_payload


class MqttBridge:
    def __init__(self,instance_id,role,service_provider,state_provider,command_handler=None,*,discovery_cache=None):
        self.instance_id,self.role=instance_id,role
        self.prefix=namespace(instance_id,role)
        self.service_provider,self.state_provider,self.command_handler=service_provider,state_provider,command_handler
        self.session_nonce=secrets.token_hex(16)
        self.client=None
        self.connected=False
        self.queue=asyncio.Queue(maxsize=128)
        self.configs={}
        self.discovery_cache=Path(discovery_cache) if discovery_cache else None
        if self.discovery_cache and self.discovery_cache.exists():
            try:
                if self.discovery_cache.stat().st_size>1024*1024: raise ValueError()
                saved=json.loads(self.discovery_cache.read_bytes())
                if not isinstance(saved,list) or len(saved)>10000: raise ValueError()
                uid='ha_tunnel_'+instance_id+'_'+role+'_'
                for topic in saved:
                    if not isinstance(topic,str) or not topic.startswith('homeassistant/') or '/'+uid not in topic or not topic.endswith('/config'): raise ValueError()
                self.configs={topic:'' for topic in saved}
            except (ValueError,OSError): self.state='discovery_cache_error'
        self.state='starting'
        self.task=None
        self.loop=None
        self.next_retry=0
        if self.discovery_cache:
            # Persist known identities before Ingress can delete a legacy object,
            # including when the broker has not connected yet.
            for state in self.state_provider():
                for topic in discovery_payloads(instance_id,role,state): self.configs.setdefault(topic,'')
                if role=='server':
                    uid=f'ha_tunnel_{instance_id}_{role}_{state["client_id"]}'
                    for action in ('start','pause'):
                        self.configs.setdefault(f'homeassistant/button/{uid}/{action}/config','')
            atomic_write(self.discovery_cache,json.dumps(sorted(self.configs)).encode())

    def status(self): return {'state':self.state}

    def _enqueue(self,event):
        def put():
            try: self.queue.put_nowait(event)
            except asyncio.QueueFull: self.state='queue_full'
        if self.loop and not self.loop.is_closed(): self.loop.call_soon_threadsafe(put)

    def _on_connect(self,client,userdata,flags,reason,properties):
        self._enqueue(('connect',not reason.is_failure))

    def _on_disconnect(self,client,userdata,flags,reason,properties): self._enqueue(('disconnect',))

    def _on_message(self,client,userdata,message):
        if len(message.payload)<=2048: self._enqueue(('message',message.topic,bytes(message.payload),message.retain))

    async def start(self):
        self.loop=asyncio.get_running_loop()
        await self._setup()
        self.task=asyncio.create_task(self._loop())

    async def _setup(self):
        try:
            service=await self.service_provider()
            if service is None:
                self.state='not_configured'; self.next_retry=time.monotonic()+30; return
            client=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id='hat-'+self.instance_id+'-'+self.role,protocol=mqtt.MQTTv5)
            client.username_pw_set(service.username,service.password)
            if service.ssl: client.tls_set()
            client.will_set(self.prefix+'/availability','offline',qos=1,retain=True)
            client.on_connect=self._on_connect; client.on_disconnect=self._on_disconnect; client.on_message=self._on_message
            client.reconnect_delay_set(1,60)
            self.client=client
            client.connect_async(service.host,service.port,keepalive=30,clean_start=True)
            client.loop_start()
            self.state='connecting'
            self.next_retry=time.monotonic()+60
        except Exception:
            self.state='service_error'; self.next_retry=time.monotonic()+30

    async def handle_command(self,topic,payload,retained):
        # MQTT publishers cannot attest an authenticated HA administrator.
        # Keep a fail-closed handler for queued/legacy messages during upgrades.
        return

    def _publish(self,topic,payload,retain=False):
        info=self.client.publish(topic,payload,qos=1,retain=retain)
        if info.rc!=mqtt.MQTT_ERR_SUCCESS: raise ValueError('MQTT publish failed')
        return info

    async def reconcile(self,force=False):
        if not self.connected or self.client is None: return
        try:
            self._publish(self.prefix+'/availability','online',True)
            present={}
            for client in self.state_provider():
                cid=client['client_id']
                for topic,config in discovery_payloads(self.instance_id,self.role,client).items():
                    raw=json.dumps(config,separators=(',',':'),sort_keys=True)
                    present[topic]=raw
                    if force or self.configs.get(topic)!=raw: self._publish(topic,raw,True)
                self._publish(f'{self.prefix}/{cid}/state',json.dumps(state_payload(client),separators=(',',':')))
                if self.role=='server':
                    self._publish(f'{self.prefix}/{cid}/controls','online' if client.get('editable') and not client.get('revoked') else 'offline',True)
            for topic in self.configs.keys()-present.keys():
                info=self._publish(topic,'',True)
                await asyncio.to_thread(info.wait_for_publish,2)
                if not info.is_published(): raise ValueError('Discovery removal not acknowledged')
            if self.discovery_cache:
                atomic_write(self.discovery_cache,json.dumps(sorted(present)).encode())
            self.configs=present
            self.state='connected'
        except Exception: self.state='publish_error'

    async def _loop(self):
        while True:
            try: event=await asyncio.wait_for(self.queue.get(),5)
            except asyncio.TimeoutError: event=None
            if event:
                if event[0]=='connect':
                    self.connected=event[1]
                    if self.connected:
                        self.client.subscribe('homeassistant/status',qos=1)
                        await self.reconcile(force=True)
                    else: self.state='connection_rejected'
                elif event[0]=='disconnect': self.connected=False; self.state='offline'
                elif event[0]=='message':
                    if event[1]=='homeassistant/status' and event[2]==b'online': await self.reconcile(force=True)
                    else: await self.handle_command(*event[1:])
            await self.reconcile()
            if not self.connected and time.monotonic()>=self.next_retry:
                if self.client:
                    await asyncio.to_thread(self.client.disconnect)
                    await asyncio.to_thread(self.client.loop_stop)
                    self.client=None
                await self._setup()

    async def close(self):
        if self.task:
            self.task.cancel(); await asyncio.gather(self.task,return_exceptions=True)
        if self.client:
            if self.connected:
                try:
                    info=self._publish(self.prefix+'/availability','offline',True)
                    await asyncio.to_thread(info.wait_for_publish,2)
                except Exception: pass
            await asyncio.to_thread(self.client.disconnect)
            await asyncio.to_thread(self.client.loop_stop)
        self.connected=False; self.state='offline'
