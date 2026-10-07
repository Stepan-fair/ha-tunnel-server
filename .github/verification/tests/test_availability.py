import sqlite3
import pytest
from server.app.availability import AvailabilityService
from tests.test_billing_store import funded, command, operations, ZONE
from tests.test_subscription_calendar import stamp

class Clock:
    reliable=True
    def __init__(self,now): self.value=now
    def now(self): return self.value

async def healthy(): return dict(frp=True,gateway=True,npm=True)

@pytest.mark.parametrize('hours,extra,days',[(12,0,0),(12,1,1),(24,0,1),(30,0,1),(36,0,1),(36,1,2),(48,0,2),(60,1,3)])
async def test_checkpoint_recovery_compensates_once(tmp_path,hours,extra,days):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]); store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy)
    await service.recover(); assert await service.sample()
    before=snap['billing']['paid_until']
    clock.value+=hours*3600+extra
    restarted=AvailabilityService(store,clock,probe=healthy)
    await restarted.recover(); await restarted.recover()
    state=store.access_snapshot(creds.client_id,clock.value)
    assert state['billing']['paid_until']==before+days*86400
    assert state['billing']['balance_kopecks']==60000
    assert len(operations(store,'compensation'))==(1 if days else 0)

async def test_outage_expiring_period_saved_before_mutation(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(stamp(2026,11,14,20)); store.clock=clock
    availability=AvailabilityService(store,clock,probe=healthy)
    await availability.recover()
    clock.value=stamp(2026,11,17,10)
    await AvailabilityService(store,clock,probe=healthy).recover()
    after=repo.reconcile(creds.client_id,clock.value,timezone=ZONE)
    assert after['billing']['paid_until']==stamp(2026,11,18)
    assert len(operations(store,'purchase'))==1

async def test_pause_debt_revoked_and_no_paid_period_are_ineligible(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    store.apply_access(creds.client_id,'pause','pause',snap['revision'],now[0])
    clock=Clock(now[0]); store.clock=clock
    await AvailabilityService(store,clock,probe=healthy).recover()
    clock.value+=86400*4
    await AvailabilityService(store,clock,probe=healthy).recover()
    assert store.access_snapshot(creds.client_id,clock.value)['billing']['paid_until']==snap['billing']['paid_until']
    assert not operations(store,'compensation')

async def test_probe_failure_distinct_episodes_and_bad_clock(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]); store.clock=clock
    signals=dict(frp=True,gateway=True,npm=True)
    async def probe(): return signals.copy()
    service=AvailabilityService(store,clock,probe=probe)
    await service.recover()
    signals['npm']=False
    clock.value+=1
    assert not await service.sample()
    clock.value+=13*3600
    signals['npm']=True
    assert await service.sample()
    assert len(operations(store,'compensation'))==1
    clock.reliable=False; clock.value+=86400*5
    assert not await service.sample()
    assert len(operations(store,'compensation'))==1

async def test_failed_checkpoint_rolls_back_healthy_and_entitlements(tmp_path,monkeypatch):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]); store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy)
    await service.recover()
    before=store.get_metadata('service_last_healthy')
    original=service._checkpoint
    def fail(db,now):
        original(db,now)
        raise sqlite3.OperationalError('test fault')
    monkeypatch.setattr(service,'_checkpoint',fail)
    clock.value+=1
    with pytest.raises(sqlite3.Error): await service.sample()
    assert store.get_metadata('service_last_healthy')==before

async def test_individual_client_offline_does_not_start_shared_outage(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]); store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy)
    await service.recover()
    clock.value+=13*3600
    assert await service.sample()
    assert not operations(store,'compensation')
    assert store.access_snapshot(creds.client_id,clock.value)['billing']['paid_until']==snap['billing']['paid_until']

async def test_backwards_checkpoint_is_rejected(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]); store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy)
    await service.recover()
    clock.value-=100
    assert not await service.sample()
    assert store.get_metadata('service_last_healthy')==now[0]

@pytest.mark.parametrize('variant',['unpaid','revoked','zero'])
async def test_unpaid_revoked_and_zero_excluded(tmp_path,variant):
    store,creds,repo,now,snap=funded(tmp_path)
    if variant=='unpaid':
        command(repo,creds.client_id,'set_balance',0,now[0])
        now[0]=stamp(2026,11,16)
        repo.reconcile(creds.client_id,now[0],timezone=ZONE)
    if variant=='revoked': store.revoke(creds.client_id)
    if variant=='zero': command(repo,creds.client_id,'set_price',0,now[0])
    clock=Clock(now[0]); store.clock=clock
    await AvailabilityService(store,clock,probe=healthy).recover()
    clock.value+=86400*2
    await AvailabilityService(store,clock,probe=healthy).recover()
    assert not operations(store,'compensation')
