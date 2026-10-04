import json
import pytest
from shared.discovery import discovery_payloads, state_payload
from shared.mqtt import MqttBridge


def client():
    return {'client_id':'b'*32,'domain':'alpha.example.org','revision':2,'access_state':'allowed','editable':True,
            'paused':False,'expired':False,'revoked':False,'deadline':None,'telemetry':{},
            'code_hash':'PRIVATE','secret':'PRIVATE','invitation':'PRIVATE'}


def test_discovery_existing_future_and_roles():
    a=discovery_payloads('a'*32,'server',client())
    b=discovery_payloads('a'*32,'client',client())
    assert len(a)==17 and len(b)==17 and set(a).isdisjoint(b)
    assert a==discovery_payloads('a'*32,'server',client())
    assert 'PRIVATE' not in json.dumps(a)+json.dumps(state_payload(client()))
    assert sum('/button/' in topic for topic in a)==0
    assert all(config.get('expire_after')==45 for topic,config in a.items() if '/button/' not in topic)


async def test_retained_and_old_session_commands_never_execute():
    calls=[]
    async def provider(): return None
    async def handler(*args,**kwargs): calls.append(args)
    bridge=MqttBridge('a'*32,'server',provider,lambda:[client()],handler)
    data={'action':'pause','client_id':'b'*32,'revision':2,'session_nonce':bridge.session_nonce}
    topic=bridge.prefix+'/b'+'b'*31+'/command'
    await bridge.handle_command(topic,json.dumps(data).encode(),True)
    assert not calls
    data['session_nonce']='old'
    await bridge.handle_command(topic,json.dumps(data).encode(),False)
    assert not calls
    data['session_nonce']=bridge.session_nonce
    await bridge.handle_command(topic,json.dumps(data).encode(),False)
    await bridge.handle_command(topic,json.dumps(data).encode(),False)
    assert not calls  # MQTT cannot authenticate an administrative HA user.


async def test_missing_broker_is_optional():
    async def provider(): return None
    bridge=MqttBridge('a'*32,'server',provider,lambda:[client()])
    await bridge.start()
    assert bridge.status()['state']=='not_configured'
    await bridge.close()


async def test_birth_and_new_clients_republish_discovery():
    records=[]
    clients=[client()]
    async def provider(): return None
    class Info: rc=0
    class Broker:
        def publish(self,topic,payload,**kwargs): records.append((topic,payload,kwargs)); return Info()
    bridge=MqttBridge('a'*32,'server',provider,lambda:clients)
    bridge.client=Broker(); bridge.connected=True
    await bridge.reconcile()
    assert sum(topic.startswith('homeassistant/') for topic,_,_ in records)==17
    records.clear()
    other={**client(),'client_id':'c'*32,'domain':'bravo.example.org'}
    clients.append(other)
    await bridge.reconcile()
    assert sum(topic.startswith('homeassistant/') for topic,_,_ in records)==17
    records.clear()
    await bridge.reconcile(force=True)
    assert sum(topic.startswith('homeassistant/') for topic,_,_ in records)==34
    assert all(info['retain'] for topic,_,info in records if topic.startswith('homeassistant/'))
    assert all(not info['retain'] for topic,_,info in records if topic.endswith('/state'))
