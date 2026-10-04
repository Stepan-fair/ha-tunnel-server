"""MQTTv5 retained-command behavior against an actual isolated Mosquitto."""
import asyncio
import json
import shutil
from types import SimpleNamespace
import pytest
import paho.mqtt.client as mqtt
from test_frp import unused_port
from shared.mqtt import MqttBridge
from shared.supervisor_services import MqttService
from server.app.store import Store
from server.app.access import AccessService

pytestmark=pytest.mark.skipif(not shutil.which('mosquitto'),reason='Requires real Mosquitto')


async def test_real_mqtt_cannot_change_access_even_with_legacy_nonce(tmp_path):
    port=unused_port()
    config=tmp_path/'mosquitto.conf'
    config.write_text(f'listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\n')
    process=await asyncio.create_subprocess_exec('mosquitto','-c',str(config),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
    store=Store(tmp_path/'state.db','example.org',clock=lambda:2000)
    c=store.redeem(store.issue('alpha',1000).code,1001)
    store.set_capabilities(c.client_id,['access-v1'])
    class Relay:
        from collections import defaultdict
        locks=defaultdict(asyncio.Lock)
        async def disconnect(self,cid): pass
    access=AccessService(store,Relay(),store.clock)
    async def provider(): return MqttService('127.0.0.1',port,'synthetic','synthetic')
    bridge=MqttBridge('a'*32,'server',provider,store.list_clients,access.command)
    sender=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,protocol=mqtt.MQTTv5)
    try:
        for _ in range(100):
            try:
                r,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();break
            except OSError: await asyncio.sleep(.05)
        await bridge.start()
        for _ in range(100):
            if bridge.connected: break
            await asyncio.sleep(.05)
        assert bridge.connected
        sender.connect('127.0.0.1',port); sender.loop_start()
        data={'action':'pause','client_id':c.client_id,'revision':0,'session_nonce':bridge.session_nonce}
        topic=f'{bridge.prefix}/{c.client_id}/command'
        # Neither retained nor fresh payloads can provide administrative identity.
        info=sender.publish(topic,json.dumps(data),qos=1,retain=True)
        await asyncio.to_thread(info.wait_for_publish,2)
        await asyncio.sleep(.25)
        assert store.access_snapshot(c.client_id,2000)['revision']==0
        for _ in range(2):
            info=sender.publish(topic,json.dumps(data),qos=1,retain=False)
            await asyncio.to_thread(info.wait_for_publish,2)
        await asyncio.sleep(.5)
        assert store.access_snapshot(c.client_id,2000)['revision']==0
        assert store.access_snapshot(c.client_id,2000)['access_state']=='allowed'
    finally:
        await bridge.close()
        sender.disconnect(); await asyncio.to_thread(sender.loop_stop)
        process.terminate(); await process.wait()
