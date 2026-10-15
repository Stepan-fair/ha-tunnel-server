import asyncio
import socket
import ssl
import threading
import time
from types import SimpleNamespace

import pytest

from shared import mqtt as module
from shared.supervisor_services import MqttService
from tests.test_mqtt_outbox import WireBroker, until


@pytest.mark.parametrize('reachable',[True,False])
def test_numeric_stalled_ipv6_preserves_ipv4_chance_and_closes_losers(monkeypatch,reachable):
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(); listener.settimeout(1)
    port=listener.getsockname()[1]; original_socket=socket.socket; candidates=[]; cancelled=[]
    class TrackedSocket(original_socket):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            if self.family==socket.AF_INET6: candidates.append(self)
        def connect(self,address):
            if self.family==socket.AF_INET6:
                # Causal old synchronous dial consumes the whole deadline.
                time.sleep(self.gettimeout()); raise TimeoutError('Synthetic IPv6 blackhole')
            return super().connect(address)
    monkeypatch.setattr(socket,'socket',TrackedSocket)
    for loop_type in {asyncio.SelectorEventLoop,getattr(asyncio,'ProactorEventLoop',asyncio.SelectorEventLoop)}:
        connect=loop_type.sock_connect
        async def stalled(loop,sock,address,original=connect):
            if sock.family==socket.AF_INET6:
                try: await asyncio.Future()
                finally: cancelled.append(sock)
            else: return await original(loop,sock,address)
        monkeypatch.setattr(loop_type,'sock_connect',stalled)
    def forbidden(*args,**kwargs): raise AssertionError('Numeric dial must not invoke DNS/executor')
    monkeypatch.setattr(socket,'getaddrinfo',forbidden)
    monkeypatch.setattr(asyncio.BaseEventLoop,'run_in_executor',forbidden)
    client=module.mqtt.Client(module.mqtt.CallbackAPIVersion.VERSION2); client.connect_timeout=.6
    addresses=[(socket.AF_INET6,socket.SOCK_STREAM,6,'',('::1',port,0,0))]
    if reachable: addresses.append((socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',port)))
    started=time.monotonic(); connected=None
    try:
        if reachable:
            connected=module._numeric_connection(client,addresses)
            peer,_=listener.accept(); peer.close()
            assert connected.gettimeout()==.6 and connected.getblocking()
        else:
            with pytest.raises(OSError): module._numeric_connection(client,addresses)
        assert time.monotonic()-started<1.2
        assert candidates and cancelled==candidates
        assert all(sock.fileno()==-1 for sock in candidates)
    finally:
        if connected is not None: connected.close()
        listener.close()


@pytest.mark.parametrize('source',['explicit','environment','default'])
def test_unsupported_proxy_fails_closed_before_numeric_dial(monkeypatch,source):
    client=module.mqtt.Client(module.mqtt.CallbackAPIVersion.VERSION2)
    if source=='explicit': client._proxy={'proxy_addr':'proxy.invalid'}
    if source=='environment': monkeypatch.setenv('mqtt_proxy','socks://proxy.invalid:1080')
    if source=='default': monkeypatch.setattr(module.mqtt,'socks',SimpleNamespace(get_default_proxy=lambda:('synthetic',)))
    calls=[]
    def forbidden(*args,**kwargs): calls.append(args); raise AssertionError('Proxy must not fall back to direct dial')
    monkeypatch.setattr(socket,'socket',forbidden)
    with pytest.raises(OSError,match='proxy unsupported'):
        module._numeric_connection(client,[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',1883))])
    assert not calls


@pytest.mark.parametrize('mode',['valid','wrong_ca','wrong_name'])
async def test_real_paho_keeps_tls_identity_without_worker_dns(tmp_path,monkeypatch,mode):
    from server.app.pki import ensure_pki
    pki=ensure_pki(tmp_path/'pki','mqtt.example.org')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(pki.cert,pki.key)
    sni=[]; context.set_servername_callback(lambda sock,name,ctx:sni.append(name))
    wire=WireBroker()
    wire.server=await asyncio.start_server(wire.accept,'127.0.0.1',0,ssl=context)
    wire.port=wire.server.sockets[0].getsockname()[1]
    hostname='wrong.example.org' if mode=='wrong_name' else 'mqtt.example.org'
    async def service(): return MqttService(hostname,wire.port,'synthetic','synthetic',True)
    async def resolve(host,port):
        assert host==hostname and port==wire.port
        # IPv6 refusal exercises address-family fallback without changing SNI.
        return [(socket.AF_INET6,socket.SOCK_STREAM,6,'',('::1',port,0,0)),
                (socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',port))]
    monkeypatch.setattr(module,'getaddrinfo',resolve)
    tls_set=module.mqtt.Client.tls_set
    def trusted(client): return tls_set(client,ca_certs=None if mode=='wrong_ca' else str(pki.ca))
    monkeypatch.setattr(module.mqtt.Client,'tls_set',trusted)
    attempted_dns=[]
    def forbidden(*args,**kwargs):
        attempted_dns.append(threading.current_thread().name)
        raise AssertionError('Network thread attempted OS DNS')
    monkeypatch.setattr(socket,'getaddrinfo',forbidden)
    bridge=module.MqttBridge('a'*32,'server',service,lambda:[])
    try:
        await bridge.start()
        if mode=='valid':
            await until(lambda:bridge.connected)
            assert bridge.client._host==hostname and bridge.client._ssl_context.check_hostname
        else:
            await until(lambda:not bridge._network.is_alive())
            assert not bridge.connected and not wire.connections
        assert sni==[hostname] and not attempted_dns
    finally: await bridge.close(); await wire.close()


def test_global_workers_remain_owned_across_loops_and_recover(monkeypatch):
    release=threading.Event(); entered=[]; loops=[]; bridges=[]
    class SlowClient:
        def __init__(self,*a,**kw): pass
        def max_queued_messages_set(self,*a): pass
        def max_inflight_messages_set(self,*a): pass
        def username_pw_set(self,*a): pass
        def will_set(self,*a,**kw): pass
        def connect(self,*a,**kw): entered.append(self); release.wait(5)
        def loop_forever(self,*a,**kw): loops.append(self)
        def disconnect(self): pass
    monkeypatch.setattr(module.mqtt,'Client',SlowClient)
    monkeypatch.setattr(module,'STOP_TIMEOUT',.01)
    monkeypatch.setattr(module,'_WORKER_LIMIT',2)
    async def resolve(*args): return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',1883))]
    monkeypatch.setattr(module,'getaddrinfo',resolve)
    async def service(): return MqttService('mqtt.example.org',1883,'u','p',False)
    async def cycle(identity):
        bridge=module.MqttBridge(identity*32,'server',service,lambda:[]); bridges.append(bridge)
        await bridge.start(); await asyncio.sleep(.01); await bridge.close()
    try:
        for identity in ['a','a','a','b','c','d']: asyncio.run(cycle(identity))
        assert len(entered)==2, 'Same identity and finite global capacity survive new loops'
        release.set()
        for bridge in bridges:
            if bridge._network: bridge._network.join(1)
        assert loops==[], 'Late connection after close must not revive MQTT'
        asyncio.run(cycle('a'))
        assert len(entered)==3, 'Retired worker releases capacity for a fresh connection'
    finally:
        release.set()
        for bridge in bridges:
            if bridge._network: bridge._network.join(1)


async def test_cancelled_mqtt_dns_is_reaped_and_fresh_bridge_recovers(tmp_path,monkeypatch):
    from shared import dns
    worker=tmp_path/'blocked.py'; worker.write_text('import time\ntime.sleep(60)\n')
    original=dns._worker; spawn=asyncio.create_subprocess_exec; children=[]
    async def tracked(*args,**kwargs):
        child=await spawn(*args,**kwargs); children.append(child); return child
    monkeypatch.setattr(asyncio,'create_subprocess_exec',tracked)
    monkeypatch.setattr(dns,'_worker',str(worker)); monkeypatch.setattr(dns,'_DEADLINE',.3)
    wire=await WireBroker().start()
    async def service(): return MqttService('localhost',wire.port,'u','p',False)
    bridges=[]
    try:
        first=module.MqttBridge('a'*32,'server',service,lambda:[]); bridges.append(first)
        task=asyncio.create_task(first.start()); await until(lambda:bool(children))
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        async def recreate():
            bridge=module.MqttBridge('a'*32,'server',service,lambda:[]); bridges.append(bridge)
            await bridge.start(); await bridge.close()
        # Recreate during one DNS lifetime. Serial callers now share and await
        # each job, so forty serial starts correctly span forty reaped jobs.
        await asyncio.gather(*(recreate() for _ in range(40)))
        assert len(children)==1 and all(bridge._network is None for bridge in bridges)
        assert await asyncio.wait_for(asyncio.to_thread(lambda:'progress'),.5)=='progress'
        await asyncio.wait_for(children[0].wait(),2); await asyncio.sleep(.02)
        monkeypatch.setattr(dns,'_worker',original); monkeypatch.setattr(dns,'_DEADLINE',4)
        recovered=module.MqttBridge('a'*32,'server',service,lambda:[]); bridges.append(recovered)
        await recovered.start(); await until(lambda:recovered.connected)
        assert len(children)==2
    finally:
        for bridge in bridges: await bridge.close()
        for child in children:
            if child.returncode is None: child.kill()
            await child.wait()
        await wire.close()
