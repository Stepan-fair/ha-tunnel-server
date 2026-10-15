"""Executable pinned-FRP acceptance tests; Linux is a required separate gate.

No production endpoints, network privileges or endpoint protection changes.
A local TCP bridge injects disconnections; Linux /proc measures actual socket
counts after settling (admission counts alone cannot prove FRP bounds).
"""
import asyncio
from collections import Counter
from contextlib import asynccontextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import ssl
import sys
from urllib.parse import urlsplit

import pytest
from aiohttp import ClientSession, TCPConnector, ClientTimeout, web
from aiohttp.test_utils import TestServer
from aiohttp.abc import AbstractResolver
from test_frp import environment, FRPS, FRPC, wait_http
from client.app.runtime import ClientRuntime
from shared.runtime import FrpRuntime
from server.app.policy import authorize
from server.app.relay import ClientRelay
from server.app.telemetry import TelemetryService

pytestmark = pytest.mark.skipif(sys.platform != 'linux' or not FRPS or not FRPC,
    reason='Requires actual pinned Linux FRP binaries; Windows skips are not acceptance')


async def eventually(predicate, timeout=30):
    async with asyncio.timeout(timeout):
        while not predicate(): await asyncio.sleep(.1)


def socket_count(pid):
    count=0
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try: count += os.readlink(fd).startswith('socket:')
        except FileNotFoundError: pass  # Concurrently closing a socket is normal.
    return count


@asynccontextmanager
async def bridge(destination, *, tls=None):
    writers=set()
    tasks=set()
    async def forward(reader, writer):
        while data:=await reader.read(65536):
            writer.write(data)
            await writer.drain()
    async def handle(reader, writer):
        tasks.add(asyncio.current_task())
        remote=None
        pumps=[]
        try:
            other,remote=await asyncio.open_connection('127.0.0.1',destination)
            writers.update((writer,remote))
            pumps=[asyncio.create_task(forward(reader,remote)),asyncio.create_task(forward(other,writer))]
            await asyncio.wait(pumps,return_when=asyncio.FIRST_COMPLETED)
        except (ConnectionError,OSError):
            pass  # Expected while the destination restarts.
        finally:
            for pump in pumps: pump.cancel()
            await asyncio.gather(*pumps,return_exceptions=True)
            for stream in (writer,remote):
                if stream is not None:
                    writers.discard(stream)
                    stream.close()
            tasks.discard(asyncio.current_task())
    server=await asyncio.start_server(handle,'127.0.0.1',0,ssl=tls)
    try: yield server.sockets[0].getsockname()[1],writers
    finally:
        server.close(); await server.wait_closed()
        for writer in tuple(writers): writer.close()
        for task in tuple(tasks): task.cancel()
        await asyncio.gather(*tuple(tasks),return_exceptions=True)


class LoopbackResolver(AbstractResolver):
    async def resolve(self,host,port=0,family=socket.AF_INET):
        return [{'hostname':host,'host':'127.0.0.1','port':port,'family':socket.AF_INET,'proto':0,'flags':0}]
    async def close(self): pass


async def test_real_clone_cannot_replace_http_wss_or_grow_sockets(environment,tmp_path):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    a,b=clients
    # Use actual production ClientRuntime so each clone gets a fresh launch nonce.
    owner=ClientRuntime(FRPC,tmp_path/'owner.json')
    peer=ClientRuntime(FRPC,tmp_path/'peer.json')
    try:
        await owner.start(a[2]); await peer.start(b[2])
        await wait_http(session,url,a[0].domain,'alpha')
        await wait_http(session,url,b[0].domain,'bravo')
        epoch=store.admission.epoch(a[0].client_id,0)
        assert epoch
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(pki.cert,pki.key)
        trust=ssl.create_default_context(cafile=str(pki.ca))
        async with bridge(urlsplit(url).port,tls=tls) as (tls_port,_):
            async with ClientSession(connector=TCPConnector(ssl=trust,resolver=LoopbackResolver()),timeout=ClientTimeout(total=5)) as secure:
                async with secure.ws_connect(f'wss://tunnel.example.org:{tls_port}/ws',headers={'Host':a[0].domain}) as ws:
                    await ws.send_str('before'); assert (await ws.receive(timeout=5)).data=='before'
                    baseline=socket_count(server.process.pid)
                    for i in range(8):
                        clone=ClientRuntime(FRPC,tmp_path/f'clone-{i}.json')
                        config=deepcopy(a[2]); config['loginFailExit']=True
                        try:
                            await clone.start(config)
                            await asyncio.wait_for(clone.process.wait(),15)
                            assert clone.process.returncode != 0
                        finally: await clone.stop()
                        assert store.admission.epoch(a[0].client_id,0)==epoch
                        await ws.send_str(str(i)); assert (await ws.receive(timeout=5)).data==str(i)
                    await asyncio.sleep(1)
                    assert socket_count(server.process.pid)<=baseline+2
        assert store.admission.counts()=={'owners':2,'reservations':0,'active':2}
        await wait_http(session,url,b[0].domain,'bravo')
    finally: await owner.stop(); await peer.stop()


async def test_real_native_reconnect_and_server_restart(environment,tmp_path,monkeypatch):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    c,_,config=clients[0]
    calls=[]
    def observe(op,content,*args):
        result=authorize(op,content,*args)
        if op=='Login' and not result['reject']: calls.append(deepcopy(result['content']))
        return result
    monkeypatch.setattr('server.app.web.authorize',observe)
    owner=ClientRuntime(FRPC,tmp_path/'bridge-owner.json')
    async with bridge(port) as (bridge_port,writers):
        config=deepcopy(config); config['serverPort']=bridge_port
        try:
            await owner.start(config)
            await wait_http(session,url,c.domain,'alpha')
            first=calls[-1]
            baseline=socket_count(server.process.pid)
            for _ in range(4):
                count=len(calls)
                for writer in tuple(writers): writer.close()
                await eventually(lambda:len(calls)>count)
                await wait_http(session,url,c.domain,'alpha')
                assert calls[-1]['run_id']==first['run_id']
                assert calls[-1]['client_id']==c.client_id
                assert calls[-1]['metas']['ha_tunnel_session']!=first['metas']['ha_tunnel_session']
            await asyncio.sleep(1)
            assert socket_count(server.process.pid)<=baseline+2
            old={'user':first['user'],'run_id':first['run_id'],'metas':first['metas']}
            current_epoch=store.admission.epoch(c.client_id,0)
            assert authorize('Ping',{'user':old,'privilege_key':authority.issue(c.client_id)},store,authority)['reject']
            assert authorize('CloseProxy',{'user':old,'proxy_name':c.client_id+'.ha'},store,authority)['reject']
            assert store.admission.epoch(c.client_id,0)==current_epoch
            before=store.access_snapshot(c.client_id,store.now())
            count=len(calls)
            await server.restart()
            assert store.admission.counts()['owners']==0
            await eventually(lambda:len(calls)>count)
            await wait_http(session,url,c.domain,'alpha')
            after=store.access_snapshot(c.client_id,store.now())
            for key in ('client_id','domain','generation','revision','balance_minor'):
                if key in before: assert after[key]==before[key]
        finally: await owner.stop()


async def test_real_legacy_restart_waits_for_owner_lease(environment,tmp_path):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    c,legacy,config=clients[0]  # The shared runtime deliberately sends no nonce.
    offset=[0.0]
    loop=asyncio.get_running_loop()
    store.admission.clock=lambda:loop.time()+offset[0]
    await legacy.start(config)
    await wait_http(session,url,c.domain,'alpha')
    epoch=store.admission.epoch(c.client_id,0)
    await legacy.stop()
    clone=FrpRuntime(FRPC,tmp_path/'fresh-legacy.json')
    try:
        await clone.start(config)
        await asyncio.sleep(3)
        assert store.admission.epoch(c.client_id,0)==epoch
        offset[0]+=121  # Advance policy clock only; binary process and callbacks remain real.
        await wait_http(session,url,c.domain,'alpha')
        await eventually(lambda:store.admission.epoch(c.client_id,0) not in (None,epoch))
    finally: await clone.stop()


async def test_real_registration_rejected_after_allowed_callback_is_not_ha_proof(environment,monkeypatch):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    a,b=clients
    target=web.Application()
    async def hello(request): return web.Response(text=request.host.split('.')[0])
    async def ha_greeting(request):
        ws=web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({'type':'auth_required','ha_version':'2026.9.4'})
        async for _ in ws: pass
        return ws
    target.router.add_get('/',hello)
    target.router.add_get('/api/websocket',ha_greeting)
    async with TestServer(target) as ha:
        # Both clients target a HA-shaped endpoint. Without the registration
        # fault, either client's actual telemetry probe can succeed.
        for _,_,config in clients: config['proxies'][0]['localPort']=ha.port
        await a[1].start(a[2]); await wait_http(session,url,a[0].domain,'alpha')
        relay=ClientRelay(store,store.now,upstream_port=urlsplit(url).port)
        await relay.start(port=0)
        telemetry=TelemetryService(store,relay,store.now)
        try:
            await telemetry.probe_once(a[0].client_id)
            healthy=telemetry.snapshot(a[0].client_id)
            assert healthy['frp_connected'] and healthy['ha_available']
            assert healthy['rtt_ms'] is not None
            accepted=[]
            def conflict(op,content,*args):
                result=authorize(op,content,*args)
                if op=='NewProxy' and not result['reject'] and content['user']['user']==b[0].client_id:
                    accepted.append(True)
                    # Test-only fault injection AFTER production policy accepts:
                    # frps must reject the existing global proxy name.
                    result=deepcopy(result)
                    result['content']['proxy_name']=a[0].client_id+'.ha'
                return result
            monkeypatch.setattr('server.app.web.authorize',conflict)
            await b[1].start(b[2]); await eventually(lambda:bool(accepted))
            await asyncio.sleep(.5)
            assert store.admission.connected(b[0].client_id,0)
            async with session.get(url,headers={'Host':b[0].domain}) as response:
                assert response.status!=200
            await telemetry.probe_once(b[0].client_id)
            result=telemetry.snapshot(b[0].client_id)
            assert result['frp_connected'] and not result['ha_available']
            assert result['rtt_ms'] is None
            await telemetry.probe_once(a[0].client_id)
            assert telemetry.snapshot(a[0].client_id)['ha_available']
            await wait_http(session,url,a[0].domain,'alpha')
        finally:
            await telemetry.close(); await relay.close()
            await a[1].stop(); await b[1].stop()


def control_socket_count(pid,port):
    """Actual established server-side control TCPs; no work connections in this test."""
    inodes=set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try: link=os.readlink(fd)
        except FileNotFoundError: continue
        if link.startswith('socket:['): inodes.add(link[8:-1])
    count=0
    for line in Path(f'/proc/{pid}/net/tcp').read_text().splitlines()[1:]:
        fields=line.split()
        if int(fields[1].split(':')[1],16)==port and fields[3]=='01' and fields[9] in inodes:
            count+=1
    return count


async def test_real_reservation_churn_has_one_control_socket(environment,tmp_path,monkeypatch,record_testsuite_property):
    store,authority,server,plugin,pki,clients,session,url,port=environment
    c,_,config=clients[0]
    changed_config=deepcopy(server.config)
    changed_config['transport']['tcpMux']=False
    await server.stop()
    await server.start(changed_config)  # start persists config; restart only relaunches it.
    server_pid=server.process.pid
    assert json.loads(server.path.read_text())['transport']['tcpMux'] is False
    # Do not let loginFailExit candidates race the new server's startup.
    async with asyncio.timeout(15):
        while True:
            try:
                _,writer=await asyncio.open_connection('127.0.0.1',urlsplit(url).port)
                writer.close(); await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(.1)
    calls=[]
    operations=Counter()
    def no_activity(op,content,*args):
        if op in ('Ping','NewWorkConn','NewProxy'):
            operations[(op,'rejected')]+=1
            return {'reject':True,'reject_reason':'isolated test: keep reservation unconfirmed'}
        result=authorize(op,content,*args)
        operations[(op,'rejected' if result['reject'] else 'accepted')]+=1
        if op=='Login' and not result['reject']: calls.append(deepcopy(result['content']))
        return result
    monkeypatch.setattr('server.app.web.authorize',no_activity)
    offset=[0.0]
    store.admission.clock=lambda:asyncio.get_running_loop().time()+offset[0]
    runtimes=[]
    samples=[]
    try:
        for i in range(8):
            count=len(calls)
            candidate=deepcopy(config)
            candidate['transport']['tcpMux']=False
            # FRP v0.71.0 heartbeatWorker/BackoffUntil sends its first Ping
            # immediately; rejecting it closes the control via Pong.Error.
            # This login-only fixture must send no activity at all. The server
            # heartbeat timeout and production client heartbeats stay intact.
            candidate['transport']['heartbeatInterval']=-1
            candidate['proxies']=[]
            candidate['loginFailExit']=True
            runtime=ClientRuntime(FRPC,tmp_path/f'reservation-{i}.json')
            runtimes.append(runtime)
            await runtime.start(candidate)
            await eventually(lambda:len(calls)>count)
            await asyncio.sleep(.5)  # Plugin acceptance precedes FRP control activation.
            await eventually(lambda:control_socket_count(server_pid,port)==1)
            for _ in range(3):
                await asyncio.sleep(.2)
                assert control_socket_count(server_pid,port)==1
            samples.append(control_socket_count(server_pid,port))
            assert store.admission.counts()=={'owners':1,'reservations':1,'active':0}
            offset[0]+=16
        assert len({call['run_id'] for call in calls})==1
        assert all(call['client_id']==c.client_id for call in calls)
        assert len({call['metas']['ha_tunnel_session'] for call in calls})==len(calls)
        assert operations[('Ping','rejected')]==0
        record_testsuite_property('reservation_churn.stabilized_control_socket_counts',json.dumps(samples))
        record_testsuite_property('reservation_churn.plugin_operations',json.dumps({
            ':'.join(key):value for key,value in sorted(operations.items())}))
    except BaseException:
        # Only bounded numeric state: never dump FRP config, Login payloads,
        # tokens, process nonces, RunIDs, session epochs or raw child output.
        try:
            sockets={'all':socket_count(server_pid),'control':control_socket_count(server_pid,port)}
        except OSError:
            sockets={'unavailable':True}
        print('reservation_churn_diagnostic',json.dumps({
            'iteration':len(samples),'samples':samples,
            'server_pid':server_pid,'server_status':server.status(),
            'sockets':sockets,
            'client_statuses':[runtime.status() for runtime in runtimes],
            'accepted_logins':len(calls),'admission':store.admission.counts(),
            'distinct_epochs':len({call['metas']['ha_tunnel_session'] for call in calls}),
            'operations':{':'.join(key):value for key,value in sorted(operations.items())},
            'tcp_mux':False,'heartbeat_interval':candidate['transport']['heartbeatInterval'],
        },sort_keys=True))
        raise
    finally:
        for runtime in runtimes: await runtime.stop()
