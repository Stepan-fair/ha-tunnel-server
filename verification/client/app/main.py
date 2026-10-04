import asyncio
import json
import os
from pathlib import Path
import time
import secrets
import re

from shared.files import atomic_write
from shared.service import listen,shutdown_event
from shared.runtime import FrpRuntime
from client.app.controller import Controller
from client.app.supervisor import Supervisor
from client.app.web import make_app
from shared.mqtt import MqttBridge
from shared.supervisor_services import mqtt_service
from shared.supervisor_client import SupervisorClient
from shared.ha_admin import verified_admin


async def main():
    os.umask(0o077)
    options=json.loads(Path('/data/options.json').read_bytes())
    try:
        info=await SupervisorClient(os.environ.get('SUPERVISOR_TOKEN')).get('/supervisor/info')
        options['timezone']=info.get('timezone','UTC')
    except Exception: options['timezone']='UTC'
    async def admin(user): return await verified_admin(user,os.environ.get('SUPERVISOR_TOKEN'))
    runtime=FrpRuntime('/usr/local/bin/frpc','/data/frpc.json')
    controller=Controller('/data/state','/homeassistant/configuration.yaml',runtime,Supervisor())
    instance_path=Path('/data/state/instance_id')
    if not instance_path.exists(): atomic_write(instance_path,secrets.token_hex(16).encode())
    instance_id=instance_path.read_text().strip()
    if not re.fullmatch('[a-f0-9]{32}',instance_id): raise ValueError('Invalid Client instance identity')
    def states():
        if not controller.credentials: return []
        state=controller.status()
        access=state['access'] or {}
        return [{**access,'client_id':controller.credentials['client_id'],'domain':controller.credentials['domain'],
                 'telemetry':state['telemetry']}]
    mqtt=MqttBridge(instance_id,'client',lambda:mqtt_service(os.environ.get('SUPERVISOR_TOKEN')),states,
        discovery_cache='/data/mqtt-discovery.json')
    controller.mqtt=mqtt
    runner=await listen(make_app(controller,options,admin_check=admin),'0.0.0.0',18991)
    async def watch():
        while True:
            await controller.monitor_once()
            atomic_write('/tmp/ha-tunnel-health',str(int(time.time())).encode())
            await asyncio.sleep(15)
    tasks=[]
    try:
        await mqtt.start()
        if controller.credentials:
            atomic_write('/data/state/ca.pem',controller.credentials['ca_pem'].encode())
            # Resume only when the existing config is already ready; never edit
            # or restart HA automatically just because this app was restarted.
            await controller.resume()
        tasks=[asyncio.create_task(watch()),asyncio.create_task(shutdown_event())]
        done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done: task.result()
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await runner.cleanup()
        await runtime.stop()
        await mqtt.close()


if __name__=='__main__':
    try:
        asyncio.run(main())
    except Exception:
        print('HA Tunnel Client stopped: verify HA configuration and ports 18991/18992.',flush=True)
        raise SystemExit(1)
