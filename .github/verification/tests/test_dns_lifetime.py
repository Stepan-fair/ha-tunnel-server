"""Cancelled network owners must not leave unbounded OS DNS jobs."""
import asyncio
import socket

import pytest

from server.app.npm_dependency import NpmDependency
from shared.supervisor_client import SupervisorClient


def test_actual_children_are_reaped_when_event_loops_are_recreated(monkeypatch,tmp_path):
    from shared import dns
    worker=tmp_path/'loop_dns.py'; worker.write_text('import time\ntime.sleep(60)\n')
    children=[]; spawn=asyncio.create_subprocess_exec
    async def tracked(*args,**kwargs):
        child=await spawn(*args,**kwargs);children.append(child);return child
    monkeypatch.setattr(asyncio,'create_subprocess_exec',tracked)
    monkeypatch.setattr(dns,'_worker',str(worker))
    async def cancelled():
        task=asyncio.create_task(dns.getaddrinfo('recreated.invalid',443))
        count=len(children)
        async with asyncio.timeout(2):
            while len(children)==count: await asyncio.sleep(.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        # asyncio.run now cancels its remaining owned job and reaps the child.
    for _ in range(8):
        asyncio.run(cancelled())
        assert children[-1].returncode is not None
        assert not dns._active
    assert len(children)==8


@pytest.mark.parametrize('path', ['npm', 'supervisor', 'mqtt', 'admin', 'core'])
async def test_recreated_owners_bound_underlying_dns_and_recover(monkeypatch, tmp_path, path):
    from shared import dns
    worker = tmp_path / 'blocked_dns.py'
    worker.write_text('import time\ntime.sleep(60)\n')
    children = []
    real = asyncio.create_subprocess_exec
    original_worker = dns._worker

    async def spawn(*args, **kwargs):
        process = await real(*args, **kwargs)
        children.append(process)
        return process

    class Supervisor:
        async def get(self, path):
            return dict(slug='a0d7b954_nginxproxymanager', hostname='a0d7b954-nginxproxymanager',
                        repository='a0d7b954', state='started', host_network=False, ip_address='172.30.33.9')

    async def attempt():
        if path == 'npm':
            return await NpmDependency(Supervisor()).snapshot({'npm_host': 'a0d7b954-nginxproxymanager'})
        if path == 'mqtt':
            from shared.supervisor_services import mqtt_service
            return await mqtt_service('synthetic-token')
        if path == 'admin':
            from shared.ha_admin import verified_admin
            return await verified_admin('synthetic-user','synthetic-token')
        if path == 'core':
            from client.app.supervisor import Supervisor as CoreSupervisor
            monkeypatch.setenv('SUPERVISOR_TOKEN','synthetic-token')
            return await CoreSupervisor().get_http_config()
        return await SupervisorClient('synthetic-token').get('/host/info')

    monkeypatch.setattr(dns, '_worker', str(worker))
    monkeypatch.setattr(dns, '_DEADLINE', .25)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    try:
        first = asyncio.create_task(attempt())
        for _ in range(100):
            if children: break
            await asyncio.sleep(.005)
        first.cancel()
        with pytest.raises(asyncio.CancelledError): await first
        for _ in range(80):
            try:
                async with asyncio.timeout(.005):
                    await attempt()
            except (TimeoutError, ValueError, OSError):
                pass
        assert len(children) == 1, 'one owned DNS child must survive owner recreation'
        assert await asyncio.wait_for(asyncio.to_thread(lambda: 'progress'), .5) == 'progress'
        await asyncio.wait_for(children[0].wait(), 2)
        assert children[0].returncode is not None
        await asyncio.sleep(.02)
        monkeypatch.setattr(dns, '_worker', original_worker)
        monkeypatch.setattr(dns, '_DEADLINE', 4)
        rows = await dns.getaddrinfo('localhost', 443, socket.AF_INET)
        assert rows and all(row[4][0] == '127.0.0.1' for row in rows)
        assert len(children) == 2
    finally:
        for child in children:
            if child.returncode is None: child.kill()
            await child.wait()


async def test_supervisor_collects_complete_fragmented_body(monkeypatch):
    from aiohttp import web, ClientSession
    from aiohttp.test_utils import TestServer
    from shared import supervisor_client

    async def fragment(request):
        response = web.StreamResponse(headers={'Content-Type': 'application/json'})
        await response.prepare(request)
        await response.write(b'{"result":"ok","data":')
        await asyncio.sleep(.02)
        await response.write(b'{"dt_synchronized":true}}')
        await response.write_eof()
        return response

    app = web.Application()
    app.router.add_get('/host/info', fragment)
    server = TestServer(app)
    await server.start_server()
    class RoutedSession:
        def __init__(self, **kwargs): self.session = ClientSession(**kwargs)
        async def __aenter__(self): return self
        async def __aexit__(self, *args): await self.session.close()
        def request(self, method, url, **kwargs):
            return self.session.request(method, str(server.make_url('/host/info')), **kwargs)
    monkeypatch.setattr(supervisor_client.aiohttp, 'ClientSession', RoutedSession)
    try:
        assert await SupervisorClient('synthetic-token').get('/host/info') == {'dt_synchronized': True}
    finally:
        await server.close()


async def test_dns_budget_has_no_queue_and_survives_cancelled_callers(monkeypatch, tmp_path):
    from shared import dns
    worker = tmp_path / 'slow.py'
    worker.write_text('import time\ntime.sleep(60)\n')
    monkeypatch.setattr(dns, '_worker', str(worker))
    monkeypatch.setattr(dns, '_DEADLINE', .5)
    children = []
    real = asyncio.create_subprocess_exec
    async def spawn(*args, **kwargs):
        child = await real(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    tasks = [asyncio.create_task(dns.getaddrinfo(f'test-{i}.invalid', 443)) for i in range(8)]
    try:
        for _ in range(100):
            if len(children) == 8: break
            await asyncio.sleep(.005)
        assert len(children) == 8
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for i in range(80):
            with pytest.raises(OSError, match='busy'):
                await dns.getaddrinfo(f'extra-{i}.invalid', 443)
        assert len(children) == 8
        await asyncio.wait_for(asyncio.gather(*(p.wait() for p in children)), 2)
        assert all(p.returncode is not None for p in children)
    finally:
        for child in children:
            if child.returncode is None: child.kill()
            await child.wait()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(.02)


async def test_dns_deadline_during_spawn_reaps_late_child(monkeypatch, tmp_path):
    from shared import dns
    worker = tmp_path / 'slow.py'
    worker.write_text('import time\ntime.sleep(60)\n')
    monkeypatch.setattr(dns, '_worker', str(worker))
    monkeypatch.setattr(dns, '_DEADLINE', .02)
    children = []
    real = asyncio.create_subprocess_exec
    async def spawn(*args, **kwargs):
        await asyncio.sleep(.08)
        child = await real(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    with pytest.raises(OSError): await dns.getaddrinfo('late.invalid', 443)
    with pytest.raises(OSError, match='busy'): await dns.getaddrinfo('late.invalid', 443)
    for _ in range(100):
        if children and children[0].returncode is not None: break
        await asyncio.sleep(.01)
    assert len(children) == 1 and children[0].returncode is not None


async def test_default_dns_deadline_reaps_and_allows_same_key_recovery(monkeypatch,tmp_path):
    from shared import dns
    worker=tmp_path/'blocked.py';worker.write_text('import time\ntime.sleep(60)\n')
    original=dns._worker;monkeypatch.setattr(dns,'_worker',str(worker))
    assert dns._DEADLINE==4
    started=asyncio.get_running_loop().time()
    with pytest.raises(OSError):await dns.getaddrinfo('localhost',443,socket.AF_INET)
    elapsed=asyncio.get_running_loop().time()-started
    assert 3.8<=elapsed<6 and not dns._active
    monkeypatch.setattr(dns,'_worker',original)
    assert (await dns.getaddrinfo('localhost',443,socket.AF_INET))[0][4][0]=='127.0.0.1'


async def test_status_recreation_cannot_orphan_resolver_jobs(monkeypatch,tmp_path):
    import threading
    from shared import dns
    from client.app.status import ClientStatusClient
    gate=threading.Event();legacy=[];children=[]
    original=socket.getaddrinfo;spawn=asyncio.create_subprocess_exec
    def blocked(*args,**kwargs):
        legacy.append(True);gate.wait(5)
        return original('localhost',443)
    async def child(*args,**kwargs):
        result=await spawn(*args,**kwargs);children.append(result);return result
    worker=tmp_path/'slow.py';worker.write_text('import time\ntime.sleep(60)\n')
    monkeypatch.setattr(socket,'getaddrinfo',blocked)
    monkeypatch.setattr(asyncio,'create_subprocess_exec',child)
    monkeypatch.setattr(dns,'_worker',str(worker));monkeypatch.setattr(dns,'_DEADLINE',.5)
    try:
        for _ in range(3):
            client=ClientStatusClient('https://status.example.org')
            task=asyncio.create_task(client.fetch('a'*32,'synthetic'))
            await asyncio.sleep(.03);task.cancel()
            await asyncio.gather(task,return_exceptions=True);await client.close()
        assert len(children)==1 and not legacy, (len(children),len(legacy))
        await asyncio.wait_for(children[0].wait(),2)
    finally:
        gate.set()
        for process in children:
            if process.returncode is None:process.kill()
            await process.wait()
        await asyncio.sleep(.02)


async def test_failed_kill_keeps_one_slot_until_real_child_is_reaped(monkeypatch,tmp_path):
    from shared import dns
    worker=tmp_path/'slow.py';worker.write_text('import time\ntime.sleep(60)\n')
    monkeypatch.setattr(dns,'_worker',str(worker));monkeypatch.setattr(dns,'_DEADLINE',.05)
    monkeypatch.setattr(dns,'_REAP_DEADLINE',.03)
    spawn=asyncio.create_subprocess_exec;children=[]
    async def child(*args,**kwargs):
        process=await spawn(*args,**kwargs);children.append(process)
        class DeniedKill:
            stdout=process.stdout
            @property
            def returncode(self):return process.returncode
            def kill(self):raise OSError('synthetic kill denial')
            async def wait(self):return await process.wait()
        return DeniedKill()
    monkeypatch.setattr(asyncio,'create_subprocess_exec',child)
    try:
        with pytest.raises(OSError):await dns.getaddrinfo('quarantine.invalid',443)
        for _ in range(80):
            with pytest.raises(OSError,match='busy'):await dns.getaddrinfo('quarantine.invalid',443)
        assert len(children)==1 and children[0].returncode is None and len(dns._active)==1
        assert await asyncio.wait_for(asyncio.to_thread(lambda:True),.5)
    finally:
        for process in children:
            if process.returncode is None:process.kill()
            await process.wait()
        await asyncio.sleep(.02)
    assert not dns._active


@pytest.mark.parametrize('body',["print('not-json')","print('x'*65536)","raise SystemExit(1)"])
async def test_bad_dns_child_output_is_bounded_and_releases_slot(monkeypatch,tmp_path,body):
    from shared import dns
    worker=tmp_path/'bad.py';worker.write_text(body,encoding='utf-8')
    monkeypatch.setattr(dns,'_worker',str(worker))
    with pytest.raises(OSError):await dns.getaddrinfo('bad.invalid',443)
    assert not dns._active


@pytest.mark.parametrize('failure',['eof','size','invalid','timeout'])
async def test_supervisor_rejects_incomplete_oversize_and_timed_out_body(monkeypatch,failure):
    from aiohttp import web,ClientSession,ClientTimeout
    from aiohttp.test_utils import TestServer
    from shared import supervisor_client
    async def body(request):
        response=web.StreamResponse(headers={'Content-Type':'application/json'})
        if failure=='eof':response.content_length=100
        await response.prepare(request)
        if failure=='timeout':
            await asyncio.sleep(.1)
        elif failure=='size':await response.write(b' '*65537)
        else:await response.write(b'{"result":"ok","data":')
        if failure=='eof':request.transport.close()
        return response
    app=web.Application();app.router.add_get('/host/info',body)
    async with TestServer(app) as server:
        class RoutedSession:
            def __init__(self,**kwargs):
                if failure=='timeout':kwargs['timeout']=ClientTimeout(total=.03)
                self.session=ClientSession(**kwargs)
            async def __aenter__(self):return self
            async def __aexit__(self,*args):await self.session.close()
            def request(self,method,url,**kwargs):
                return self.session.request(method,str(server.make_url('/host/info')),**kwargs)
        monkeypatch.setattr(supervisor_client.aiohttp,'ClientSession',RoutedSession)
        with pytest.raises(ValueError,match='Supervisor request failed'):
            await SupervisorClient('synthetic-token').get('/host/info')
