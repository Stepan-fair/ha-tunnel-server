import asyncio
import socket
import pytest

from server.app import setup as setup_api

HOST='a0d7b954-nginxproxymanager'
SLUG='a0d7b954_nginxproxymanager'

class Supervisor:
    def __init__(self):
        self.info=dict(slug=SLUG,hostname=HOST,repository='a0d7b954',state='started',host_network=False,ip_address='172.30.33.9')
        self.error=False
    async def get(self,path):
        assert path=='/addons/'+SLUG+'/info'
        if self.error: raise ValueError('private response')
        return dict(self.info)

class Resolver:
    def __init__(self): self.addresses=['172.30.33.9']; self.error=False
    async def __call__(self,host):
        assert host==HOST
        if self.error: raise socket.gaierror()
        return self.addresses


def provider():
    from server.app.npm_dependency import NpmDependency
    sup,resolve=Supervisor(),Resolver()
    return NpmDependency(sup,resolve),sup,resolve

async def test_candidate_default_is_verified_not_arbitrary_dns(tmp_path):
    # localhost resolves, but it is not the supported Supervisor-owned NPM.
    service=setup_api.SetupService(tmp_path,Supervisor())
    with pytest.raises(ValueError): await service.candidate_validator({'npm_host':'localhost'})

async def test_verified_snapshot_requires_current_supervisor_owner_and_dns():
    dep,sup,resolve=provider()
    snap=await dep.snapshot({'npm_host':HOST})
    assert snap.addresses==('172.30.33.9',) and snap.hostname==HOST
    assert snap.fresh()
    sup.info['ip_address']='172.30.33.10'
    with pytest.raises(ValueError): await dep.snapshot({'npm_host':HOST})
    resolve.addresses=['172.30.33.9','172.30.33.10']
    with pytest.raises(ValueError): await dep.snapshot({'npm_host':HOST})
    resolve.addresses=['172.30.33.10']
    assert (await dep.snapshot({'npm_host':HOST})).addresses==('172.30.33.10',)

@pytest.mark.parametrize('change',[
    {'slug':'other_nginxproxymanager'},{'hostname':'other-service'},
    {'repository':'other'},{'host_network':True},{'ip_address':'0.0.0.0'},
    {'ip_address':'127.0.0.1'},{'ip_address':'8.8.8.8'},{'ip_address':'172.30.33.0/24'},
    {'ip_address':'::'},{'ip_address':''},{'ip_address':'224.0.0.1'},
])
async def test_foreign_identity_and_unsafe_addresses_fail_closed(change):
    dep,sup,resolve=provider(); sup.info.update(change)
    with pytest.raises(ValueError): await dep.snapshot({'npm_host':HOST})

async def test_dependency_waits_for_late_npm_dns_supervisor_without_saving():
    dep,sup,resolve=provider()
    from server.app.npm_dependency import DependencyUnavailable
    for state in ('stopped','unknown'):
        sup.info['state']=state
        with pytest.raises(DependencyUnavailable): await dep.snapshot({'npm_host':HOST})
    sup.info['state']='started'; sup.error=True
    with pytest.raises(DependencyUnavailable): await dep.snapshot({'npm_host':HOST})
    sup.error=False; resolve.error=True
    with pytest.raises(DependencyUnavailable): await dep.snapshot({'npm_host':HOST})
    resolve.error=False
    assert (await dep.snapshot({'npm_host':HOST})).addresses==('172.30.33.9',)

async def test_snapshot_expires_with_monotonic_not_wall_clock(monkeypatch):
    dep,sup,resolve=provider()
    from server.app import npm_dependency
    now=[100.0]; monkeypatch.setattr(npm_dependency.time,'monotonic',lambda:now[0])
    snap=await dep.snapshot({'npm_host':HOST})
    now[0]=129.9; assert snap.fresh()
    now[0]=130.0; assert not snap.fresh()
    now[0]=99.0; assert not snap.fresh()


class Process:
    def __init__(self): self.returncode=None; self.kills=0
    def kill(self): self.kills+=1; self.returncode=-9
    async def wait(self): return self.returncode

async def runtime_case(tmp_path,monkeypatch):
    from server.app.npm_dependency import NpmRuntime
    from server.app.gateway import Gateway
    from server.app.store import Store
    import server.app.gateway as gateway_module
    processes=[]
    async def launch(*args,**kwargs):
        process=Process(); processes.append(process); return process
    monkeypatch.setattr(gateway_module.asyncio,'create_subprocess_exec',launch)
    monkeypatch.setattr(gateway_module,'kill_gateway',lambda process:process.kill())
    dep,sup,resolve=provider()
    store=Store(tmp_path/'state.db','example.org')
    gateway=Gateway(tmp_path/'nginx.conf')
    runtime=NpmRuntime(dep,{'npm_host':HOST},store,gateway)
    return runtime,sup,resolve,store,gateway,processes

async def test_current_snapshot_changes_all_consumers_and_failed_reload_stays_closed(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    assert await runtime.refresh()
    old=processes[-1]
    assert runtime.addresses==('172.30.33.9',)
    assert 'allow 172.30.33.9;' in gateway.path.read_text()
    sup.info['ip_address']='172.30.33.10'; resolve.addresses=['172.30.33.10']
    async def failed(*a,**kw): raise OSError('cannot start')
    import server.app.gateway as gateway_module
    monkeypatch.setattr(gateway_module.asyncio,'create_subprocess_exec',failed)
    assert not await runtime.refresh()
    assert old.returncode is not None and runtime.addresses==() and runtime.current is None
    assert '172.30.33.9' not in gateway.path.read_text()
    assert runtime.status()['external']=='unknown'
    await gateway.close()

async def test_busy_expiry_closes_captured_gateway_and_resumes_after_release(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    from server.app import npm_dependency
    now=[100.]; monkeypatch.setattr(npm_dependency.time,'monotonic',lambda:now[0])
    assert await runtime.refresh()
    old=runtime.current; old_process=processes[-1]
    async with store.administration.exclusive('restore'):
        now[0]=131.
        assert not await asyncio.create_task(runtime.refresh())
        guard=asyncio.create_task(runtime.guard())
        await asyncio.sleep(0)
        guard.cancel()
        with pytest.raises(asyncio.CancelledError): await guard
        assert runtime.addresses==() and old_process.kills==1
        assert len(processes)==1
    assert await runtime.refresh()
    newer=runtime.current; new_process=processes[-1]
    runtime.expire(old)
    assert runtime.current is newer and new_process.kills==0
    sup.error=True
    assert not await runtime.refresh()
    assert runtime.addresses==() and new_process.kills==1
    await gateway.close()


async def test_guard_alone_expires_proof_during_long_administrative_busy(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from server.app import npm_dependency
    now=[100.]
    monkeypatch.setattr(npm_dependency,'time',SimpleNamespace(monotonic=lambda:now[0]))
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    assert await runtime.refresh()
    old=processes[-1]
    async with store.administration.exclusive('restore'):
        guard=asyncio.create_task(runtime.guard())
        await asyncio.sleep(0)
        now[0]=131.
        try:
            async with asyncio.timeout(2):
                while old.kills==0: await asyncio.sleep(.01)
            assert runtime.current is None and runtime.addresses==() and len(processes)==1
        finally:
            guard.cancel()
            with pytest.raises(asyncio.CancelledError): await guard
    assert await runtime.refresh()
    assert len(processes)==2 and runtime.addresses==('172.30.33.9',)
    await gateway.close()

async def test_revalidation_inflight_expiry_and_migration_do_not_reopen(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    assert await runtime.refresh()
    entered=asyncio.Event(); release=asyncio.Event()
    original=resolve.__call__
    async def blocked(host): entered.set(); await release.wait(); return await original(host)
    runtime.dependency.resolve=blocked
    pending=asyncio.create_task(runtime.refresh()); await entered.wait()
    assert store.administration.busy
    store.migrating=True
    release.set(); assert not await pending
    assert runtime.addresses==() and processes[-1].kills==1
    await gateway.close()

async def test_cancelled_revalidation_releases_exclusive_and_cannot_reopen(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    entered=asyncio.Event()
    async def blocked(host): entered.set(); await asyncio.Event().wait()
    runtime.dependency.resolve=blocked
    pending=asyncio.create_task(runtime.refresh()); await entered.wait(); pending.cancel()
    with pytest.raises(asyncio.CancelledError): await pending
    assert not store.administration.busy and runtime.addresses==() and not processes
    await gateway.close()

async def test_gateway_cancel_during_process_spawn_reaps_late_child(tmp_path,monkeypatch):
    from server.app.gateway import Gateway
    from server.app.npm_dependency import VerifiedNpmSnapshot
    import server.app.gateway as gateway_module
    entered=asyncio.Event();release=asyncio.Event();child=Process()
    async def launch(*a,**kw):
        entered.set(); await release.wait(); return child
    monkeypatch.setattr(gateway_module.asyncio,'create_subprocess_exec',launch)
    monkeypatch.setattr(gateway_module,'kill_gateway',lambda process:process.kill())
    gateway=Gateway(tmp_path/'nginx.conf')
    import time
    task=asyncio.create_task(gateway.start(VerifiedNpmSnapshot(HOST,('172.30.33.9',),time.monotonic())))
    await entered.wait();task.cancel();release.set()
    with pytest.raises(asyncio.CancelledError): await task
    assert child.kills==1 and gateway.process is None
    await gateway.close()

async def test_dead_gateway_is_waiting_and_recovers_from_same_fresh_owner(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    await runtime.refresh(); processes[-1].returncode=1
    assert runtime.status()['state']=='waiting_dependency'
    assert await runtime.refresh() and len(processes)==2
    await gateway.close()

@pytest.mark.parametrize('bad',[2887647497,True,None])
async def test_malformed_supervisor_ip_is_not_coerced(bad):
    dep,sup,resolve=provider(); sup.info['ip_address']=bad
    # ipaddress accepts integers; Supervisor protocol promises a string.
    if type(bad) is int:
        import ipaddress
        resolve.addresses=[str(ipaddress.ip_address(bad))]
    with pytest.raises(ValueError): await dep.snapshot({'npm_host':HOST})

async def test_real_resolver_selects_only_owned_ipv4_on_dual_stack_dns(monkeypatch):
    from server.app.npm_dependency import NpmDependency
    from server.app.availability_probe import NpmResolver
    from shared import dns
    sup=Supervisor(); foreign=False
    async def getaddrinfo(host,port,*,family):
        assert host==HOST and family==socket.AF_INET
        # System AF_INET selection omits the otherwise available AAAA owner.
        result=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('172.30.33.9',0))]
        if foreign: result.append((socket.AF_INET,socket.SOCK_STREAM,6,'',('172.30.33.10',0)))
        return result
    monkeypatch.setattr(dns,'getaddrinfo',getaddrinfo)
    dep=NpmDependency(sup); snap=await dep.validate_candidate({'npm_host':HOST})
    result=await NpmResolver('tunnel.example.org',snap.addresses).resolve('tunnel.example.org',443)
    assert len(result)==1 and result[0]['host']=='172.30.33.9' and result[0]['family']==socket.AF_INET
    foreign=True
    with pytest.raises(ValueError): await dep.snapshot({'npm_host':HOST})

async def test_many_dependency_failures_recover_without_lifetime_limit(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    sup.error=True
    for _ in range(200): assert not await runtime.refresh()
    sup.error=False;assert await runtime.refresh()
    assert runtime.addresses==('172.30.33.9',) and len(processes)==1
    await gateway.close()

async def test_diagnostics_distinguish_dependency_owner_from_local_service_health(tmp_path,monkeypatch):
    runtime,sup,resolve,store,gateway,processes=await runtime_case(tmp_path,monkeypatch)
    runtime.local_health=lambda:False
    await runtime.refresh()
    assert runtime.status()['local_ready'] is True and runtime.status()['local_health']=='unhealthy'
    runtime.local_health=lambda:True
    assert runtime.status()['local_health']=='healthy' and runtime.status()['external']=='unknown'
    sup.error=True; await runtime.refresh()
    assert runtime.status()['reason']=='supervisor_unavailable' and runtime.status()['local_ready'] is False
    sup.error=False;resolve.error=True;await runtime.refresh()
    assert runtime.status()['reason']=='dns_unavailable'
    await gateway.close()

@pytest.mark.parametrize('address',['192.0.2.1','198.18.0.1','198.51.100.1','203.0.113.1'])
async def test_reserved_non_rfc1918_addresses_never_become_trust(address):
    dep,sup,resolve=provider();sup.info['ip_address']=address;resolve.addresses=[address]
    with pytest.raises(ValueError): await dep.snapshot({'npm_host':HOST})

async def test_docker_host_address_ending_zero_is_valid():
    dep,sup,resolve=provider();sup.info['ip_address']='172.21.16.0';resolve.addresses=['172.21.16.0']
    assert (await dep.snapshot({'npm_host':HOST})).addresses==('172.21.16.0',)

@pytest.mark.parametrize('master_exited',[False,True])
async def test_gateway_revocation_kills_worker_group_not_only_master(tmp_path,monkeypatch,master_exited):
    import signal
    from types import SimpleNamespace
    from server.app.gateway import Gateway
    import server.app.gateway as module
    class Master(Process):
        pid=4321
    master=Master();worker_alive=True
    if master_exited: master.returncode=1
    def killpg(pid,sig):
        nonlocal worker_alive
        assert pid==4321 and sig==9
        worker_alive=False;master.returncode=-9
    monkeypatch.setattr(module,'os',SimpleNamespace(name='posix',killpg=killpg),raising=False)
    monkeypatch.setattr(module,'signal',SimpleNamespace(SIGKILL=9),raising=False)
    gateway=Gateway(tmp_path/'nginx.conf');gateway.process=master
    gateway.revoke()
    assert not worker_alive and gateway.process is None
    await gateway.close()

async def test_gateway_spawn_isolates_nginx_workers_for_bounded_revocation(tmp_path,monkeypatch):
    from server.app.gateway import Gateway
    from server.app.npm_dependency import VerifiedNpmSnapshot
    import server.app.gateway as module
    import time
    observed={}
    async def launch(*args,**kwargs): observed.update(kwargs);return Process()
    monkeypatch.setattr(module.asyncio,'create_subprocess_exec',launch)
    monkeypatch.setattr(module,'kill_gateway',lambda process:process.kill())
    gateway=Gateway(tmp_path/'nginx.conf')
    try:
        await gateway.start(VerifiedNpmSnapshot(HOST,('172.30.33.9',),time.monotonic()))
        assert observed.get('start_new_session') is True
    finally: await gateway.close()

@pytest.mark.skipif(__import__('os').name!='posix',reason='POSIX process groups require Linux')
@pytest.mark.parametrize('parent_exits',[False,True])
async def test_real_posix_gateway_group_revocation_closes_child_descriptors(tmp_path,parent_exits):
    import sys
    from server.app.gateway import Gateway
    code="import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); print(child.pid,flush=True); "+("sys.exit(0)" if parent_exits else "time.sleep(60)")
    process=await asyncio.create_subprocess_exec(sys.executable,'-c',code,start_new_session=True,
        stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
    gateway=Gateway(tmp_path/'nginx.conf');gateway.process=process
    try:
        assert int(await asyncio.wait_for(process.stdout.readline(),5))>0
        if parent_exits:
            async with asyncio.timeout(5):
                while process.returncode is None: await asyncio.sleep(.01)
        gateway.revoke()
        # Child inherited stdout: EOF proves the worker closed its descriptors too.
        assert await asyncio.wait_for(process.stdout.read(),5)==b''
        await gateway.close()
        assert process.returncode is not None
    finally:
        # Independent cleanup also reaps the child when testing a broken revoke.
        import os,signal
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        await asyncio.wait_for(process.wait(),5)
        gateway.revoke()
        await gateway.close()
