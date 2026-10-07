import asyncio
from collections import defaultdict
import pytest
from aiohttp.test_utils import TestClient,TestServer
from server.app.access import AccessService
from server.app.identity import Authority
from server.app.web import make_ingress_app
from tests.test_billing_store import funded,connected,command,operations,ZONE
from tests.test_subscription_calendar import stamp

class Relay:
    def __init__(self): self.locks=defaultdict(asyncio.Lock); self.closed=[]
    async def disconnect(self,cid): self.closed.append(cid)
    async def close(self): pass

class Clock:
    def __init__(self,now): self.value=now
    reliable=True
    def now(self): return self.value

async def test_financial_pause_closes_stream_and_topup_resumes(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    command(repo,creds.client_id,'set_balance',0,now[0])
    clock=Clock(now[0]); store.clock=clock; relay=Relay()
    service=AccessService(store,relay,clock)
    clock.value=stamp(2026,11,15)
    await service.expire_once()
    assert creds.client_id in relay.closed
    rev=store.access_snapshot(creds.client_id,clock.value)['revision']
    result=await service.billing_command(creds.client_id,'topup','pay',rev,value_kopecks=30000,timezone=ZONE)
    assert result['access_state']=='allowed'
    assert result['billing']['paid_until']==stamp(2026,12,15)

def test_pending_redeem_purchases_atomically_once(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    invite=store.issue('pending',int(now[0]))
    command(repo,invite.client_id,'set_price',30000,now[0])
    command(repo,invite.client_id,'topup',30000,now[0])
    c=store.redeem(invite.code,int(now[0]))
    assert len([r for r in operations(store,'purchase') if r['client_id']==c.client_id])==1
    store.redeem(store.reissue(c.client_id,int(now[0])).code,int(now[0]))
    assert len([r for r in operations(store,'purchase') if r['client_id']==c.client_id])==1

async def test_start_buys_new_period_manual_pause_preserved_on_reenroll(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]); store.clock=clock; service=AccessService(store,Relay(),clock)
    pause=await service.command(creds.client_id,'pause','pause',snap['revision'])
    store.revoke(creds.client_id)
    store.redeem(store.reissue(creds.client_id,int(now[0])).code,int(now[0]))
    assert store.access_snapshot(creds.client_id,clock.value)['paused']
    clock.value=stamp(2026,12,20,10)
    rev=store.access_snapshot(creds.client_id,clock.value)['revision']
    result=await service.command(creds.client_id,'start','unpause',rev)
    assert result['access_state']=='allowed'
    assert result['billing']['paid_until']==stamp(2027,1,20)
    assert len(operations(store,'purchase'))==2

async def test_billing_api_ingress_csrf_replay_and_stale(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    clock=Clock(now[0]); store.clock=clock; service=AccessService(store,Relay(),clock)
    authority=Authority(tmp_path/'identity.key','http://127.0.0.1:19000')
    options=dict(server_url='https://tunnel.example.org',admin_user_ids=['admin'],ingress_ips=['127.0.0.1'])
    async with TestClient(TestServer(make_ingress_app(store,authority,options,service.relay.disconnect,access=service))) as client:
        path='/api/clients/'+creds.client_id+'/billing'
        body=dict(action='set_price',command_id='price',revision=0,value_kopecks=30000)
        assert (await client.post(path,json=body)).status==403
        headers={'X-Remote-User-Id':'admin'}
        assert (await client.post(path,headers=headers,json=body)).status==403
        state=await(await client.get('/api/state',headers=headers)).json()
        headers['X-CSRF-Token']=state['csrf']
        response=await client.post(path,headers=headers,json=body)
        assert response.status==200
        first=await response.json()
        assert await(await client.post(path,headers=headers,json=body)).json()==first
        body['command_id']='new'
        assert (await client.post(path,headers=headers,json=body)).status==409
        body.update(revision=first['revision'],value_kopecks=True)
        assert (await client.post(path,headers=headers,json=body)).status==400

async def test_shared_outage_blocks_financial_mutation_and_tick(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(stamp(2026,11,15)); store.clock=clock
    service=AccessService(store,Relay(),clock)
    store.billing_available=lambda:False
    await service.expire_once()
    assert len(operations(store,'purchase'))==1
    from server.app.store import ConflictError
    rev=store.access_snapshot(creds.client_id,clock.value)['revision']
    with pytest.raises(ConflictError):
        await service.billing_command(creds.client_id,'topup','outage',rev,value_kopecks=30000,timezone=ZONE)
