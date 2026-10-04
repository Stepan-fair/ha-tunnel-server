import asyncio
import json
import os
from pathlib import Path
import socket
import time
from urllib.parse import urlsplit

from shared.files import atomic_write
from shared.service import listen,shutdown_event
from shared.validation import domain,origin
from server.app.store import Store
from server.app.identity import Authority
from server.app.pki import ensure_pki
from server.app.runtime import ServerRuntime,server_config
from server.app.web import make_public_app,make_plugin_app,make_ingress_app
from server.app.gateway import nginx_config
from server.app.backup import export_state,restore_state
from server.app.clock import SafeClock
from server.app.relay import ClientRelay
from server.app.access import AccessService
from server.app.telemetry import TelemetryService
from shared.mqtt import MqttBridge
from shared.supervisor_services import mqtt_service
from server.app.journal import Actor, Journal
from server.app.setup import SetupService,make_setup_app,validate_options
from shared.supervisor_client import SupervisorClient
from shared.ha_admin import verified_admin
from shared.privileges import drop_server_privileges
from shared.environment import child_environment

HEALTH_PATH=Path('/tmp/ha-tunnel-health')


async def run_setup(setup):
    reload_event=asyncio.Event()
    setup.on_saved=reload_event.set
    async def admin(user): return await verified_admin(user,os.environ.get('SUPERVISOR_TOKEN'))
    runner=await listen(make_setup_app(setup,admin),'0.0.0.0',8099)
    async def health():
        while True:
            atomic_write(HEALTH_PATH,str(int(time.time())).encode())
            await asyncio.sleep(5)
    tasks=[asyncio.create_task(health()),asyncio.create_task(shutdown_event()),asyncio.create_task(reload_event.wait())]
    try:
        done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done: task.result()
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await runner.cleanup()
    return reload_event.is_set()


async def main():
    os.umask(0o077)
    options=json.loads(Path('/data/options.json').read_bytes())
    setup=SetupService('/data',SupervisorClient(os.environ.get('SUPERVISOR_TOKEN')))
    setup.options=dict(options)
    try: await setup.detect()
    except Exception: pass  # Manual configured options remain usable if discovery is unavailable.
    try:
        options=validate_options(setup.options)
        setup.validate_existing(options)
        addresses=await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo,options['npm_host'],None,socket.AF_INET),5)
    except (ValueError,TypeError,socket.gaierror,TimeoutError):
        setup.detected['startup_problem']='Проверьте домен, адрес регистрации, занятые имена и доступность NPM. Публичный туннель пока не запущен.'
        return await run_setup(setup)
    return await run_operational(options,addresses,setup)


async def run_operational(options,addresses,setup):
    options['tunnel_host']=urlsplit(options['server_url']).hostname
    options['trusted_proxy_ips']=sorted({entry[4][0] for entry in addresses})
    options['tunnel_port']=7000
    state=Path('/data/state')
    previous=state.with_name('state.pre-restore')
    if not state.exists() and previous.exists():
        previous.rename(state)
    pki=ensure_pki(state/'pki',options['tunnel_host'])
    options['ca_pem']=pki.ca.read_text()
    store=Store(state/'state.db',options['base_domain'],options.get('reserved_names',[]),options['tunnel_host'])
    clock=SafeClock(anchor=store.get_metadata('clock_anchor',0))
    store.clock=clock
    journal=Journal(store,operations_path='/data/journal-operations.json')
    journal.startup(clock.now())
    relay=ClientRelay(store,clock)
    access=AccessService(store,relay,clock)
    telemetry=TelemetryService(store,relay,clock)
    def states():
        clients=store.list_clients()
        for client in clients: client['telemetry']=telemetry.snapshot(client['client_id'])
        return clients
    mqtt=MqttBridge(store.get_metadata('instance_id'),'server',
        lambda:mqtt_service(os.environ.get('SUPERVISOR_TOKEN')),states,
        discovery_cache='/data/mqtt-discovery.json')
    authority=Authority(state/'identity.key','http://127.0.0.1:19000')
    runtime=ServerRuntime('/usr/local/bin/frps','/data/frps.json',store,access)
    reload_event=asyncio.Event()
    setup.has_clients=lambda:bool(store.list_clients())
    setup.journal=journal
    setup.on_saved=reload_event.set
    async def restore(blob,password):
        if store.list_clients(): raise ValueError('Restore requires an empty server')
        await access.quiesce()
        await telemetry.close()
        await mqtt.close()
        await runtime.stop()
        try:
            restore_state(blob,password,state,options['base_domain'],options['tunnel_host'],options.get('reserved_names',[]))
        except Exception:
            await runtime.restart()
            relay.closing=False
            await relay.start()
            await telemetry.start()
            await mqtt.start()
            raise
        reload_event.set()
    runners=[]
    nginx=None
    tasks=[]
    try:
        await access.expire_once()
        await relay.start()
        runners.append(await listen(make_plugin_app(store,authority,options.get('bandwidth_limit_mb',10)),'127.0.0.1',19000))
        runners.append(await listen(make_public_app(store,authority,options,access,telemetry),'0.0.0.0',19001))
        async def admin(user): return await verified_admin(user,os.environ.get('SUPERVISOR_TOKEN'))
        runners.append(await listen(make_ingress_app(store,authority,options,runtime.revoke_and_disconnect,
            lambda password:export_state(state,store,password),restore,access=access,telemetry=telemetry,mqtt=mqtt,setup=setup,journal=journal,admin_check=admin),'0.0.0.0',8099))
        await runtime.start(server_config(pki))
        await telemetry.start()
        await mqtt.start()
        atomic_write('/data/nginx.conf',nginx_config(options['trusted_proxy_ips']).encode())
        nginx=await asyncio.create_subprocess_exec('nginx','-c','/data/nginx.conf','-g','daemon off;',
                    stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,env=child_environment())
        async def watch():
            delay=2
            next_renewal=0
            while True:
                if nginx.returncode is not None:
                    raise RuntimeError('Gateway process stopped')
                if not runtime.status()['running']:
                    await asyncio.sleep(delay)
                    await runtime.restart()
                    delay=min(120,delay*2)
                else:
                    delay=2
                if time.monotonic()>=next_renewal:
                    renewed=ensure_pki(state/'pki',options['tunnel_host'])
                    if renewed.renewed:
                        await runtime.restart()
                    next_renewal=time.monotonic()+86400
                atomic_write('/tmp/ha-tunnel-health',str(int(time.time())).encode())
                await asyncio.sleep(5)
        async def deadlines():
            while True:
                await access.expire_once()
                store.set_metadata('clock_anchor',clock.checkpoint())
                await asyncio.sleep(1)
        tasks=[asyncio.create_task(watch()),asyncio.create_task(deadlines()),asyncio.create_task(shutdown_event()),asyncio.create_task(reload_event.wait())]
        done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done: task.result()
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        if nginx is not None and nginx.returncode is None:
            nginx.terminate()
            await nginx.wait()
        await runtime.stop()
        await telemetry.close()
        await mqtt.close()
        await relay.close()
        store.set_metadata('clock_anchor',clock.checkpoint())
        journal.shutdown(clock.now())
        for runner in reversed(runners): await runner.cleanup()
    return reload_event.is_set()


if __name__=='__main__':
    try:
        drop_server_privileges()
        while asyncio.run(main()):
            pass
    except Exception:
        print('HA Tunnel Server stopped: verify application configuration and local ports.',flush=True)
        raise SystemExit(1)
