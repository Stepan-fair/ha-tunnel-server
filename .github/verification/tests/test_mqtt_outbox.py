import asyncio
import json
import threading
from types import SimpleNamespace

import paho.mqtt.client as mqtt
import pytest

from shared.discovery import discovery_payloads
from shared.mqtt import MqttBridge
from shared.supervisor_services import MqttService


def state(i=1):
    return dict(client_id=f'{i:032x}',domain=f'c-{i}.example.org',revision=0,
        access_state='allowed',editable=True,revoked=False,telemetry={})


async def none(): return None


class Broker:
    def __init__(self, ack=False):
        self.ack=ack
        self.sent=[]
    def publish(self,topic,payload,**kwargs):
        info=mqtt.MQTTMessageInfo(1)  # Deliberate MID reuse; identity is the object.
        if self.ack: info._set_as_published()  # ACK before publish returns.
        self.sent.append((topic,payload,kwargs,info))
        return info


class WireBroker:
    def __init__(self):
        self.ack=False; self.reject=False; self.pending_acks=[]; self.records=[]; self.connections=[]; self.tasks=set()
    async def start(self):
        self.server=await asyncio.start_server(self.accept,'127.0.0.1',0)
        self.port=self.server.sockets[0].getsockname()[1]
        return self
    async def accept(self,reader,writer):
        self.tasks.add(asyncio.current_task()); self.connections.append(writer)
        number=len(self.connections)
        try:
            while True:
                kind=(await reader.readexactly(1))[0]
                size=0; shift=0
                while True:
                    byte=(await reader.readexactly(1))[0]
                    size+=(byte&127)<<shift; shift+=7
                    if not byte&128: break
                data=await reader.readexactly(size)
                if kind>>4==1: writer.write(b'\x20\x03\x00\x00\x00')
                elif kind>>4==3:
                    length=int.from_bytes(data[:2],'big'); topic=data[2:2+length].decode()
                    mid=data[2+length:4+length]
                    payload=data[5+length:].decode()  # Client has no PUBLISH properties.
                    self.records.append((number,topic,payload,kind&1))
                    if self.ack: writer.write(b'\x40\x04'+mid+b'\x80\x00' if self.reject else b'\x40\x02'+mid)
                    else: self.pending_acks.append((writer,mid))
                elif kind>>4==12: writer.write(b'\xd0\x00')
                elif kind>>4==14: break
                await writer.drain()
        except (asyncio.IncompleteReadError,ConnectionError): pass
        finally:
            writer.close(); await writer.wait_closed(); self.tasks.discard(asyncio.current_task())
    async def close(self):
        self.server.close(); await self.server.wait_closed()
        for writer in self.connections: writer.close()
        await asyncio.gather(*tuple(self.tasks),return_exceptions=True)


async def until(predicate,timeout=3):
    async with asyncio.timeout(timeout):
        while not predicate(): await asyncio.sleep(.01)


async def test_real_paho_500_no_puback_attempts_are_bounded():
    wire=await WireBroker().start()
    async def service(): return MqttService('127.0.0.1',wire.port,'u','p',False)
    bridge=MqttBridge('a'*32,'server',service,lambda:[state()])
    try:
        await bridge.start(); await until(lambda:bridge.connected)
        for _ in range(510): await bridge.reconcile()
        # Observe installed Paho's actual queue: application bounds alone fail.
        assert len(bridge.client._out_messages)<=256
        assert bridge.status()['pending']<=4096
        assert bridge.status()['pending_bytes']<=4*1024*1024
        await until(lambda:len(wire.records)>=20)
        assert len(wire.records)<=20
        assert all(not retained for _,topic,_,retained in wire.records if topic.endswith('/state'))
    finally: await bridge.close(); await wire.close()


async def test_manifest_reserved_before_first_publish_and_tombstone_removed_only_after_ack(tmp_path):
    clients=[]; path=tmp_path/'discovery.json'
    bridge=MqttBridge('a'*32,'server',none,lambda:clients,discovery_cache=path)
    clients.append(state())
    class Crash(Broker):
        def publish(self,topic,payload,**kwargs):
            if topic.endswith('/config'):
                assert topic in json.loads(path.read_text()), 'Unreserved discovery published'
                raise RuntimeError('crash after reservation')
            return super().publish(topic,payload,**kwargs)
    bridge.client=Crash(); bridge.connected=True
    await bridge.reconcile()
    expected=set(discovery_payloads('a'*32,'server',state()))
    assert expected<=set(json.loads(path.read_text()))
    clients.clear()
    restarted=MqttBridge('a'*32,'server',none,lambda:clients,discovery_cache=path)
    broker=Broker(); restarted.client=broker; restarted.connected=True
    await restarted.reconcile()
    assert expected<=set(json.loads(path.read_text()))
    for topic,payload,_,info in broker.sent:
        if topic.endswith('/config'): assert payload==''; info._set_as_published()
    await restarted.reconcile()
    assert json.loads(path.read_text())==[]


def test_corrupt_manifest_original_is_preserved_and_delivery_fails_closed(tmp_path):
    path=tmp_path/'discovery.json'; original=b'{invalid original'
    path.write_bytes(original)
    bridge=MqttBridge('a'*32,'server',none,lambda:[state()],discovery_cache=path)
    assert path.read_bytes()==original
    assert bridge.status()['state']=='discovery_cache_error'


async def test_callback_birth_burst_schedules_only_one_handoff():
    bridge=MqttBridge('a'*32,'server',none,lambda:[])
    callbacks=[]
    bridge.loop=SimpleNamespace(is_closed=lambda:False,call_soon_threadsafe=callbacks.append)
    bridge.client=object()
    message=SimpleNamespace(topic='homeassistant/status',payload=b'online',retain=False)
    for _ in range(10000): bridge._on_message(bridge.client,None,message)
    assert len(callbacks)==1
    callbacks.pop()()
    assert bridge.queue.qsize()<=1


async def test_more_cold_topics_than_pending_budget_eventually_progress_and_churn(tmp_path):
    clients=[state(i) for i in range(1,281)]
    path=tmp_path/'discovery.json'
    bridge=MqttBridge('a'*32,'server',none,lambda:clients,discovery_cache=path)
    broker=Broker(ack=True); bridge.client=broker; bridge.connected=True
    for _ in range(35):
        await bridge.reconcile()
        assert bridge.status()['pending']<=4096
        assert bridge.status()['pending_bytes']<=4*1024*1024
        assert path.stat().st_size<=1024*1024
    expected={t for c in clients for t in discovery_payloads('a'*32,'server',c)}
    assert expected<={t for t,p,_,_ in broker.sent if p and t.endswith('/config')}
    clients[:140]=[state(i) for i in range(300,440)]
    for _ in range(40): await bridge.reconcile()
    current={t for c in clients for t in discovery_payloads('a'*32,'server',c)}
    assert set(json.loads(path.read_text()))==current
    assert current<={t for t,p,_,_ in broker.sent if p and t.endswith('/config')}


async def test_old_instance_mid_reuse_ack_cannot_remove_new_tombstone(tmp_path):
    clients=[state()]; path=tmp_path/'discovery.json'
    bridge=MqttBridge('a'*32,'server',none,lambda:clients,discovery_cache=path)
    first=Broker(); bridge.client=first; bridge.connected=True
    await bridge.reconcile()
    clients.clear()
    second=Broker(); bridge.client=second
    await bridge.reconcile()
    for _,_,_,info in first.sent: info._set_as_published()
    await bridge.reconcile()
    assert json.loads(path.read_text())
    for _,_,_,info in second.sent: info._set_as_published()
    await bridge.reconcile()
    assert json.loads(path.read_text())==[]

async def test_negative_puback_race_never_forgets_tombstone(tmp_path):
    clients=[state()]; path=tmp_path/'discovery.json'
    bridge=MqttBridge('a'*32,'server',none,lambda:clients,discovery_cache=path)
    class Reject(Broker):
        rejecting=False
        def publish(self,topic,payload,**kwargs):
            info=super().publish(topic,payload,**kwargs)
            if self.rejecting:
                bridge._on_publish(self,None,info.mid,SimpleNamespace(is_failure=True),None)
            info._set_as_published()
            return info
    broker=Reject(); bridge.client=broker; bridge.connected=True
    await bridge.reconcile()
    clients.clear(); broker.rejecting=True
    await bridge.reconcile()
    assert json.loads(path.read_text()), 'A negative PUBACK is not durable deletion proof'


async def test_replaced_oversized_unsent_message_is_not_delivered_as_current():
    from shared.mqtt_outbox import MqttOutbox
    outbox=MqttOutbox(max_bytes=100)
    broker=Broker(); outbox.bind(broker)
    assert outbox.offer('state','old')
    assert not outbox.offer('state','new'*100)
    outbox.drain()
    assert broker.sent==[], 'Overflow must not dispatch a superseded desired value'


async def test_real_reconnect_sends_only_fresh_state_and_slow_ack_recovers():
    wire=await WireBroker().start(); clients=[state()]
    async def service(): return MqttService('127.0.0.1',wire.port,'u','p',False)
    bridge=MqttBridge('a'*32,'server',service,lambda:clients)
    try:
        await bridge.start(); await until(lambda:bridge.connected)
        await until(lambda:any(t.endswith('/state') for _,t,_,_ in wire.records))
        old=bridge.client
        clients[0]['access_state']='paused'
        wire.connections[0].transport.abort()
        await until(lambda:bridge.client is not old and bridge.connected,5)
        new=bridge.client
        wire.ack=True
        for writer,mid in wire.pending_acks:
            if not writer.is_closing(): writer.write(b'\x40\x02'+mid)
        await until(lambda:any(n>1 and t.endswith('/state') for n,t,_,_ in wire.records),5)
        later=[json.loads(p) for n,t,p,_ in wire.records if n>1 and t.endswith('/state')]
        assert later and all(value['access_state']=='paused' for value in later)
        assert new is not old
        # The first slow-ACK connection remains bounded; the next source refresh
        # is rebuilt without copying its queued old state.
        await until(lambda:bridge.status()['pending']<20,5)
    finally: await bridge.close(); await wire.close()


async def test_unacknowledged_connection_is_retired_on_age_limit(monkeypatch):
    wire=await WireBroker().start()
    async def service(): return MqttService('127.0.0.1',wire.port,'u','p',False)
    bridge=MqttBridge('a'*32,'server',service,lambda:[state()])
    monkeypatch.setattr('shared.mqtt.ACK_TIMEOUT',.1)
    try:
        await bridge.start(); await until(lambda:bridge.connected)
        first=bridge.client
        await until(lambda:bridge.client is not first,3)
        assert bridge.status()['pending']==0
    finally: await bridge.close(); await wire.close()


async def test_blocked_connect_close_is_bounded_and_late_result_never_revives(monkeypatch):
    import shared.mqtt as module
    entered=threading.Event(); release=threading.Event(); loops=[]; instances=[]
    class SlowClient:
        def __init__(self,*a,**kw): instances.append(self)
        def max_queued_messages_set(self,*a): pass
        def max_inflight_messages_set(self,*a): pass
        def username_pw_set(self,*a): pass
        def will_set(self,*a,**kw): pass
        def connect(self,*a,**kw): entered.set(); release.wait(3)
        def loop_forever(self,*a,**kw): loops.append(self)
        def disconnect(self): pass
    monkeypatch.setattr(module.mqtt,'Client',SlowClient)
    monkeypatch.setattr(module,'STOP_TIMEOUT',.02)
    async def service(): return MqttService('localhost',1883,'u','p',False)
    bridge=MqttBridge('a'*32,'server',service,lambda:[])
    try:
        await bridge.start(); await until(entered.is_set)
        await bridge._reset('test')
        await bridge._setup(); await bridge._setup()
        assert len(instances)==1, 'Quarantine must prohibit extra stuck threads'
        await asyncio.wait_for(bridge.close(),.2)
        release.set()
        await until(lambda:not bridge._network.is_alive())
        assert loops==[] and bridge.client is None and not bridge.connected
    finally: release.set(); await bridge.close()


def test_bridge_recreation_across_event_loops_bounds_actual_dns_threads(monkeypatch):
    import socket
    import shared.mqtt as module
    release=threading.Event();entered=[];bridges=[]
    def blocked(*args,**kwargs):
        entered.append(threading.current_thread())
        release.wait(5)
        raise OSError('synthetic DNS unavailable')
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(module,'STOP_TIMEOUT',.01)
    async def service():return MqttService('blocked.invalid',1883,'synthetic','synthetic',False)
    async def cycle():
        bridge=MqttBridge('a'*32,'server',service,lambda:[]);bridges.append(bridge)
        await bridge.start();await asyncio.sleep(.04);await bridge.close()
    try:
        for _ in range(3):asyncio.run(cycle())
        assert len(entered)<=1, 'A new event loop must not detach a blocked DNS worker'
    finally:
        release.set()
        for bridge in bridges:
            if bridge._network:bridge._network.join(1)


def test_pending_count_and_bytes_include_sent_and_superseding_payloads():
    from shared.mqtt_outbox import MqttOutbox
    outbox=MqttOutbox(); broker=Broker(); outbox.bind(broker)
    accepted=sum(outbox.offer(str(i),'x') for i in range(5001))
    assert accepted==4096 and outbox.pending==4096
    outbox.drain()
    assert outbox.pending==4096 and len(broker.sent)==256
    assert not outbox.offer('0','replacement')  # Adds desired alongside sent.
    outbox=MqttOutbox(); outbox.bind(broker)
    for i in range(1000): outbox.offer(str(i),'x'*8192)
    assert outbox.bytes<=4*1024*1024 and outbox.pending<1000


async def test_manifest_count_and_byte_budgets_preserve_original_and_recover(tmp_path):
    path=tmp_path/'discovery.json'
    topics=[f'homeassistant/a/ha_tunnel_{"a"*32}_server_{i}/config' for i in range(10000)]
    path.write_text(json.dumps(topics,separators=(',',':')))
    bridge=MqttBridge('a'*32,'server',none,lambda:[state()],discovery_cache=path)
    broker=Broker(); bridge.client=broker; bridge.connected=True
    await bridge.reconcile()
    assert bridge.status()['state']=='discovery_manifest_full'
    assert set(json.loads(path.read_text()))==set(topics)
    assert all(not payload for topic,payload,_,_ in broker.sent if topic.endswith('/config'))
    broker.ack=True
    for _,_,_,info in broker.sent: info._set_as_published()
    for _ in range(45): await bridge.reconcile()
    assert set(json.loads(path.read_text()))==set(discovery_payloads('a'*32,'server',state()))
    # Valid JSON exceeding the byte budget is never overwritten at startup.
    original=json.dumps([topics[0]+'x'*(1024*1024)]).encode(); path.write_bytes(original)
    broken=MqttBridge('a'*32,'server',none,lambda:[],discovery_cache=path)
    assert broken.status()['state']=='discovery_cache_error' and path.read_bytes()==original

async def test_real_negative_puback_preserves_manifest_until_positive_retry(tmp_path):
    wire=await WireBroker().start(); wire.ack=True
    clients=[state()]; path=tmp_path/'discovery.json'
    async def service(): return MqttService('127.0.0.1',wire.port,'u','p',False)
    bridge=MqttBridge('a'*32,'server',service,lambda:clients,discovery_cache=path)
    try:
        await bridge.start()
        await until(lambda:path.exists() and len(json.loads(path.read_text()))==17)
        wire.reject=True; clients.clear()
        await bridge.reconcile()
        await until(lambda:any(not p and t.endswith('/config') for _,t,p,_ in wire.records))
        await asyncio.sleep(.6)
        assert len(json.loads(path.read_text()))==17
        wire.reject=False
        await until(lambda:json.loads(path.read_text())==[],5)
    finally: await bridge.close(); await wire.close()

async def test_tombstone_ack_write_failure_and_readdition_preserve_reservations(tmp_path,monkeypatch):
    import shared.mqtt as module
    path=tmp_path/'discovery.json'; clients=[state()]
    bridge=MqttBridge('a'*32,'server',none,lambda:clients,discovery_cache=path)
    broker=Broker(ack=True); bridge.client=broker; bridge.connected=True
    await bridge.reconcile()
    original=path.read_bytes(); clients.clear()
    write=module.atomic_write
    def fail(*args): raise OSError('simulated manifest write failure')
    monkeypatch.setattr(module,'atomic_write',fail)
    await bridge.reconcile()
    assert path.read_bytes()==original and bridge.state=='publish_error'
    monkeypatch.setattr(module,'atomic_write',write)
    broker.ack=False
    await bridge.reconcile()  # Retry tombstones after ACK-before-save crash.
    clients.append(state())  # Same topic desired again before those ACKs arrive.
    before_restore=len(broker.sent)
    for _,_,_,info in broker.sent: info._set_as_published()
    await bridge.reconcile()
    assert path.read_bytes()==original
    restored={topic for topic,payload,_,_ in broker.sent[before_restore:] if topic.endswith('/config') and payload}
    assert restored==set(json.loads(original)), 'Manifest identity must also regain its retained positive config'
    broker.ack=True
    for _,_,_,info in broker.sent: info._set_as_published()
    await bridge.reconcile()
    clients.clear(); await bridge.reconcile()
    assert json.loads(path.read_text())==[]

@pytest.mark.parametrize('kind',['deep','duplicate'])
def test_malformed_manifest_load_isolated_and_original_unchanged(tmp_path,kind):
    path=tmp_path/'discovery.json'
    topic=next(iter(discovery_payloads('a'*32,'server',state())))
    original=b'['*2000+b']'*2000 if kind=='deep' else json.dumps([topic,topic]).encode()
    path.write_bytes(original)
    bridge=MqttBridge('a'*32,'server',none,lambda:[state()],discovery_cache=path)
    assert bridge.status()['state']=='discovery_cache_error'
    assert path.read_bytes()==original


def test_manifest_load_read_itself_is_bounded_against_file_growth(tmp_path,monkeypatch):
    import io
    from pathlib import Path
    path=tmp_path/'discovery.json'; path.write_bytes(b'[]')
    real_open=Path.open
    class GrownFile(io.BytesIO):
        def read(self,size=-1):
            assert 0<size<=1024*1024+1, 'Manifest read must have a hard byte bound'
            return super().read(size)
    def replaced(file,mode='r',*args,**kwargs):
        if file==path and mode=='rb': return GrownFile(b' '* (2*1024*1024))
        return real_open(file,mode,*args,**kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path,'open',replaced)
        bridge=MqttBridge('a'*32,'server',none,lambda:[],discovery_cache=path)
    assert bridge.status()['state']=='discovery_cache_error'
    assert path.read_bytes()==b'[]'

def test_manifest_decoder_recursion_failure_is_optional(tmp_path,monkeypatch):
    path=tmp_path/'discovery.json'; original=b'['*2000+b']'*2000; path.write_bytes(original)
    def recursive_decoder(raw): raise RecursionError('decoder nesting limit')
    # Python versions differ in JSON decoder recursion; exercise its failure boundary.
    monkeypatch.setattr('shared.mqtt.json',SimpleNamespace(loads=recursive_decoder,dumps=json.dumps))
    bridge=MqttBridge('a'*32,'server',none,lambda:[],discovery_cache=path)
    assert bridge.status()['state']=='discovery_cache_error' and path.read_bytes()==original


@pytest.mark.parametrize('tombstone_dispatched',[False,True],ids=['queued','sent_before_ack'])
async def test_readdition_restores_retained_discovery_without_birth(tmp_path,tombstone_dispatched):
    clients=[state()]; path=tmp_path/'discovery.json'
    bridge=MqttBridge('a'*32,'server',none,lambda:clients,discovery_cache=path)
    class RetainedBroker(Broker):
        def __init__(self):
            super().__init__(ack=True)
            self.retained={}
        def publish(self,topic,payload,**kwargs):
            info=super().publish(topic,payload,**kwargs)
            if kwargs['retain'] and topic.endswith('/config'):
                if payload: self.retained[topic]=payload
                else: self.retained.pop(topic,None)
            return info
    broker=RetainedBroker(); bridge.client=broker; bridge.connected=True
    await bridge.reconcile()
    original=dict(broker.retained)
    assert len(original)==17 and all(original.values())
    clients.clear(); broker.ack=False
    if not tombstone_dispatched: bridge.outbox.max_sent=0
    await bridge.reconcile()
    assert broker.retained==({} if tombstone_dispatched else original)
    before_return=len(broker.sent)
    clients.append(state())
    # ACK the empty retained publications only after the source is present.
    for _,_,_,info in broker.sent: info._set_as_published()
    broker.ack=True; bridge.outbox.max_sent=256
    for _ in range(3): await bridge.reconcile()
    assert broker.retained==original, 'Returned source must restore broker discovery without external force'
    delivered=[(topic,payload) for topic,payload,_,_ in broker.sent[before_return:] if topic.endswith('/config')]
    assert not any(not payload for _,payload in delivered), 'A queued superseded tombstone must never be sent'
    if tombstone_dispatched: assert {topic for topic,payload in delivered if payload}==set(original)
    assert set(json.loads(path.read_text()))==set(original)
