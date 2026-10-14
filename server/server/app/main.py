import sys
from shared.diagnostics import Diagnostics

diagnostics = Diagnostics(None) if __name__=='__main__' else None
if diagnostics:
    def _early_failure(kind,error,tb):
        diagnostics.failure('startup_error',error,component='server')
    sys.excepthook=_early_failure

import asyncio
import json
import os
from pathlib import Path
import shutil
import time
from urllib.parse import urlsplit

from shared.liveness import write_heartbeat
from shared.service import listen,shutdown_event
from server.app.store import Store,ConflictError
from server.app.identity import Authority
from server.app.pki import ensure_pki
from server.app.runtime import ServerRuntime,server_config
from server.app.web import make_public_app,make_plugin_app,make_ingress_app
from server.app.gateway import Gateway
from server.app.npm_dependency import NpmRuntime,NPM_HOST
from server.app.backup import export_state,restore_state,require_empty_destination,restore_revision
from server.app.clock import SafeClock, ClockMonitor
from server.app.relay import ClientRelay
from server.app.access import AccessService
from server.app.domain_migration import DomainMigration,recover_directory
from server.app.availability import AvailabilityService
from server.app.availability_probe import ServiceProbe
from server.app.telemetry import TelemetryService
from shared.mqtt import MqttBridge
from shared.supervisor_services import mqtt_service
from server.app.journal import Actor, Journal
from server.app.setup import SetupService,make_setup_app,validate_options
from shared.supervisor_client import SupervisorClient
from shared.ha_admin import verified_admin
from shared.privileges import drop_server_privileges
from shared.http import DIAGNOSTICS
from shared.ha_notifications import HaNotifications
from shared.notification_state import NotificationState
from shared.notifications import NotificationWorker,server_snapshots

HEALTH_PATH=Path('/tmp/ha-tunnel-health')
SERVER_VERSION='0.4.3'


def phase(name,component='server'):
    if diagnostics: diagnostics.phase(name,component)


def notification_worker(directory, administration, store=None):
    """Observe lifecycle gates without reserving Administration for network I/O."""
    return NotificationWorker(NotificationState(Path(directory)/'notifications.json','server'),
        HaNotifications(os.environ.get('SUPERVISOR_TOKEN')),
        (lambda:server_snapshots(store)) if store is not None else lambda:[],
        gate=lambda:(store is None or not store.migrating) and not administration.busy)


async def run_setup(setup):
    reload_event=asyncio.Event()
    setup.on_saved=reload_event.set
    async def admin(user): return await verified_admin(user,os.environ.get('SUPERVISOR_TOKEN'))
    notifications=notification_worker(setup.directory,setup.administration)
    runner=await listen(make_setup_app(setup,admin,notifications=notifications),'0.0.0.0',8099)
    await notifications.start()
    tasks=[asyncio.create_task(shutdown_event()),asyncio.create_task(reload_event.wait())]
    try:
        while True:
            done,_=await asyncio.wait(tasks,timeout=5,return_when=asyncio.FIRST_COMPLETED)
            write_heartbeat(HEALTH_PATH)
            if done:
                for task in done: task.result()
                break
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await notifications.close()
        await runner.cleanup()
    return reload_event.is_set()


async def main():
    if diagnostics: diagnostics.install_loop(asyncio.get_running_loop())
    try: return await _main()
    except Exception as error:
        if diagnostics: diagnostics.failure('startup_error',error,component=diagnostics.active_component)
        raise


async def _main():
    os.umask(0o077)
    phase('load_options','setup')
    options=json.loads(Path('/data/options.json').read_bytes())
    setup=SetupService('/data',SupervisorClient(os.environ.get('SUPERVISOR_TOKEN')))
    setup.diagnostics=diagnostics
    setup.options=dict(options)
    phase('discovery','setup')
    try: await setup.detect()
    except Exception as error:
        if diagnostics: diagnostics.failure('discovery_error',error,component='setup',fatal=False)
    phase('validate_options','setup')
    await recover_directory(setup)
    try:
        options=validate_options(setup.options)
        setup.validate_existing(options)
        if options['npm_host']!=NPM_HOST: raise ValueError('Unsupported NPM hostname')
    except (ValueError,TypeError) as error:
        if diagnostics: diagnostics.failure('startup_error',error,component=diagnostics.active_component,fatal=False)
        setup.detected['startup_problem']='Проверьте домен, адрес регистрации, занятые имена и доступность NPM. Публичный туннель пока не запущен.'
        return await run_setup(setup)
    return await run_operational(options,setup)


async def run_operational(options,setup):
    options=dict(options)
    options['tunnel_host']=urlsplit(options['server_url']).hostname
    options['trusted_proxy_ips']=[]
    options['tunnel_port']=7000
    state=setup.directory/'state'
    previous=state.with_name('state.pre-restore')
    if not state.exists() and previous.exists(): previous.rename(state)
    phase('prepare_pki','pki')
    pki=ensure_pki(state/'pki',options['tunnel_host'])
    options['ca_pem']=pki.ca.read_text()
    phase('open_database','storage')
    store=Store(state/'state.db',options['base_domain'],options.get('reserved_names',[]),options['tunnel_host'],administration=setup.administration)
    # Listeners may serve requests during startup; compensation must precede any purchase.
    store.billing_available=lambda:False
    phase('check_clock','clock')
    clock=SafeClock(anchor=store.get_metadata('clock_anchor',0))
    store.clock=clock
    notifications=notification_worker(setup.directory,setup.administration,store)
    clock_monitor=ClockMonitor(store,clock,SupervisorClient(os.environ.get('SUPERVISOR_TOKEN')))
    journal=Journal(store,operations_path=setup.directory/'journal-operations.json')
    journal.startup(clock.now())
    relay=ClientRelay(store,clock)
    relay.diagnostics=diagnostics
    access=AccessService(store,relay,clock,diagnostics=diagnostics)
    telemetry=TelemetryService(store,relay,clock)
    telemetry.diagnostics=diagnostics
    def states():
        clients=store.list_clients()
        for client in clients: client['telemetry']=telemetry.snapshot(client['client_id'])
        return clients
    mqtt=MqttBridge(store.get_metadata('instance_id'),'server',
        lambda:mqtt_service(os.environ.get('SUPERVISOR_TOKEN')),states,
        discovery_cache=setup.directory/'mqtt-discovery.json')
    mqtt.diagnostics=diagnostics
    authority=Authority(state/'identity.key','http://127.0.0.1:19000')
    runtime=ServerRuntime('/usr/local/bin/frps',setup.directory/'frps.json',store,access,diagnostics=diagnostics)
    reload_event=asyncio.Event()
    setup.has_clients=lambda:bool(store.list_clients())
    setup.journal=journal
    setup.on_saved=reload_event.set
    migration=DomainMigration(store,setup,access)
    async def restore(blob,password,*,expected_revision):
        async with store.administration.exclusive('restore'):
            if availability is None or not availability.recovered: raise ConflictError('Wait for service startup')
            require_empty_destination(store)
            if restore_revision(store,setup.options)!=expected_revision: raise ValueError('Restore preview is stale')
            try:
                await notifications.close()
                await access.quiesce()
                await telemetry.close()
                await mqtt.close()
                await runtime.stop()
                restore_state(blob,password,state,options['base_domain'],options['tunnel_host'],options.get('reserved_names',[]),
                    current=store,expected_revision=expected_revision,configuration=setup.options)
            except Exception:
                await runtime.restart()
                relay.closing=False
                await relay.start()
                await telemetry.start()
                await mqtt.start()
                await notifications.start()
                raise
            store.migrating=True  # Keep new commands closed until the replacement state reloads.
            try: notifications.state.reset_namespace()
            except Exception:
                # Optional local delivery can never invalidate a completed restore.
                notifications.diagnostic='storage_error'
            reload_event.set()
    runners=[]
    nginx=Gateway(setup.directory/'nginx.conf',diagnostics)
    npm=NpmRuntime(setup.npm_dependency,options,store,nginx,diagnostics)
    options['npm_runtime']=npm
    setup.dependency_status=npm.status
    progress={key:time.monotonic() for key in ('clock','watch','deadlines')}
    tasks=[]
    failed=False
    availability=None
    try:
        phase('start_listeners','http')
        await relay.start()
        plugin=make_plugin_app(store,authority,options.get('bandwidth_limit_mb',10))
        public=make_public_app(store,authority,options,access,telemetry)
        if diagnostics:
            plugin[DIAGNOSTICS]=diagnostics
            public[DIAGNOSTICS]=diagnostics
        runners.append(await listen(plugin,'127.0.0.1',19000))
        runners.append(await listen(public,'0.0.0.0',19001))
        async def admin(user): return await verified_admin(user,os.environ.get('SUPERVISOR_TOKEN'))
        runners.append(await listen(make_ingress_app(store,authority,options,relay.disconnect,
            lambda password:export_state(state,store,password),restore,access=access,telemetry=telemetry,
            mqtt=mqtt,setup=setup,journal=journal,admin_check=admin,diagnostics=diagnostics,migration=migration,notifications=notifications),'0.0.0.0',8099))
        phase('start_frp','frp')
        await runtime.start(server_config(pki))
        phase('start_telemetry','telemetry')
        await telemetry.start()
        await mqtt.start()
        await notifications.start()
        if diagnostics:
            for component,task in (('mqtt',mqtt.task),('telemetry',telemetry.task),('relay',relay.flusher)):
                if task is not None: diagnostics.observe(task,component)
        # Ingress and the financial clock remain supervised during dependency waits.
        availability=AvailabilityService(store,clock,probe=ServiceProbe(runtime,nginx,options['server_url'],lambda:npm.addresses,diagnostics,generation=lambda:npm.epoch))
        npm.local_health=lambda:availability.healthy if availability.recovered else None
        store.billing_available=lambda:availability.healthy and not store.migrating
        await availability.recover()
        await access.expire_once()
        async def watch():
            delay=2
            next_renewal=0
            while True:
                if store.administration.busy or store.migrating:
                    progress['watch']=time.monotonic()
                    await asyncio.sleep(1)
                    continue
                for component,task in (('mqtt',mqtt.task),('telemetry',telemetry.task),('relay',relay.flusher)):
                    if task is not None and task.done() and not task.cancelled():
                        task.result()
                        raise RuntimeError('Background service stopped')
                if not runtime.status()['running']:
                    await asyncio.sleep(delay)
                    if store.administration.busy or store.migrating: continue
                    try: await runtime.restart()
                    except ConflictError: continue
                    delay=min(120,delay*2)
                else: delay=2
                if time.monotonic()>=next_renewal:
                    renewed=ensure_pki(state/'pki',options['tunnel_host'])
                    if renewed.renewed:
                        try: await runtime.restart()
                        except ConflictError: continue
                    next_renewal=time.monotonic()+86400
                progress['watch']=time.monotonic()
                await asyncio.sleep(5)
        async def deadlines():
            while True:
                if availability.recovered: await availability.sample()
                else: await availability.recover()
                await access.expire_once()
                if not store.administration.busy and not store.migrating and clock.reliable:
                    store.set_metadata('clock_anchor',clock.checkpoint())
                progress['deadlines']=time.monotonic()
                await asyncio.sleep(1)
        async def heartbeat():
            while True:
                write_heartbeat(HEALTH_PATH,[*progress.values(),npm.progress])
                await asyncio.sleep(5)
        phase('operational')
        if diagnostics:
            diagnostics.event('running',component='server',fields={'version':SERVER_VERSION})
            diagnostics.component('server','running')
        tasks=[asyncio.create_task(clock_monitor.run(lambda:progress.update(clock=time.monotonic())),name='clock-monitor'),asyncio.create_task(watch(),name='runtime-watch'),asyncio.create_task(deadlines(),name='deadlines'),
            asyncio.create_task(npm.run(),name='npm-dependency'),asyncio.create_task(npm.guard(),name='npm-expiry'),
            asyncio.create_task(heartbeat(),name='liveness'),
            asyncio.create_task(shutdown_event(),name='shutdown'),asyncio.create_task(reload_event.wait(),name='reload')]
        done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done: task.result()
    except BaseException as error:
        failed=True
        if diagnostics and isinstance(error,Exception):
            diagnostics.failure('service_error',error,component='server')
        raise
    finally:
        phase('cleanup')
        errors=[]
        async def cleanup(component,operation):
            try: await operation
            except Exception as error:
                errors.append(error)
                if diagnostics: diagnostics.failure('cleanup_error',error,component=component)
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await cleanup('notifications',notifications.close())
        if availability is not None: await cleanup('storage',availability.shutdown())
        npm.revoke()
        await cleanup('gateway',nginx.close())
        await cleanup('frp',runtime.stop())
        await cleanup('telemetry',telemetry.close())
        await cleanup('mqtt',mqtt.close())
        await cleanup('relay',relay.close())
        try:
            if not store.administration.busy and not store.migrating and clock.reliable:
                store.set_metadata('clock_anchor',clock.checkpoint())
            journal.shutdown(clock.now())
        except Exception as error:
            errors.append(error)
            if diagnostics: diagnostics.failure('cleanup_error',error,component='storage')
        for runner in reversed(runners): await cleanup('http',runner.cleanup())
        if errors and not failed: raise errors[0]
    return reload_event.is_set()


if __name__=='__main__':
    try:
        phase('prepare_privileges','privileges')
        drop_server_privileges()
        diagnostics.attach('/data/diagnostics')
        diagnostics.event('startup',component='server',fields={'version':SERVER_VERSION})
        diagnostics.event('phase',component='storage',fields={'free_bytes':shutil.disk_usage('/data').free})
        while asyncio.run(main()): pass
        diagnostics.shutdown()
    except Exception as error:
        diagnostics.failure('startup_error',error,component=diagnostics.active_component)
        raise SystemExit(1)
