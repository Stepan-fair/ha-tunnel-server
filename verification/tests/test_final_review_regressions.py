
import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from aiohttp.test_utils import TestClient, TestServer
from server.app.availability import AvailabilityService
from server.app.availability_probe import ServiceProbe
from shared.diagnostics import Diagnostics
from shared.presentation import format_metrics
from tests.test_availability import Clock, healthy
from tests.test_billing_store import funded, connected, command, operations
from tests.test_domain_migration import context, ready
from tests.test_subscription_calendar import stamp

async def test_completed_migration_allows_normal_settings_and_idempotent_retry(tmp_path):
    store,creds,repo,now,snap,setup,migration,draft=context(tmp_path)
    preview=await migration.preview(draft)
    result=await migration.apply(draft,'move',preview['revision'])
    current={**draft,'bandwidth_limit_mb':20,'admin_user_ids':['new-admin']}
    await setup.save(current,setup.revision(draft))
    assert await migration.recover()
    assert setup.options==current
    assert await migration.apply(draft,'move',preview['revision'])==result
    assert store.base_domain=='example.net'
    assert len(operations(store,'purchase'))==1

async def test_startup_http_cannot_purchase_before_outage_recovery(tmp_path,monkeypatch):
    import server.app.main as main
    store,creds,repo,now,snap=funded(tmp_path/'state')
    clock=Clock(stamp(2026,11,14,20));store.clock=clock
    await AvailabilityService(store,clock,probe=healthy).recover()
    clock.value=stamp(2026,11,17,10)
    original_path=main.Path
    monkeypatch.setattr(main,'Path',lambda value:tmp_path/str(value).removeprefix('/data/') if str(value).startswith('/data/') else original_path(value))
    monkeypatch.setattr(main,'Store',lambda *args,**kwargs:store)
    monkeypatch.setattr(main,'SafeClock',lambda **kwargs:clock)
    monkeypatch.setattr(main,'Journal',lambda *args,**kwargs:SimpleNamespace(startup=lambda now:None,shutdown=lambda now:None))
    monkeypatch.setattr(main,'MqttBridge',lambda *args,**kwargs:SimpleNamespace(status=lambda:{'state':'not_configured'},close=AsyncMock()))
    monkeypatch.setattr(main,'ServerRuntime',lambda *args,**kwargs:AsyncMock())
    async def admin(*args):return True
    monkeypatch.setattr(main,'verified_admin',admin)
    setup=SimpleNamespace(detected={'timezone':'Europe/Moscow'},options={},diagnostics=None)
    options=dict(base_domain='example.org',server_url='https://tunnel.example.org',admin_user_ids=['admin'],ingress_ips=['127.0.0.1'])
    responses=[]
    class StopStartup(Exception):pass
    async def listen(app,host,port):
        if port==8099:
            async with TestClient(TestServer(app)) as client:
                headers={'X-Remote-User-Id':'admin'}
                state=await(await client.get('/api/state',headers=headers)).json()
                headers['X-CSRF-Token']=state['csrf']
                body=dict(action='topup',command_id='startup-topup',revision=store.access_snapshot(creds.client_id,clock.value)['revision'],value_kopecks=1)
                responses.append((await client.post('/api/clients/'+creds.client_id+'/billing',headers=headers,json=body)).status)
            raise StopStartup()
        return SimpleNamespace(cleanup=AsyncMock())
    monkeypatch.setattr(main,'listen',listen)
    with pytest.raises(StopStartup):
        await main.run_operational(options,[(None,None,None,None,('127.0.0.1',0))],setup)
    assert responses==[409]
    assert len(operations(store,'purchase'))==1
    await AvailabilityService(store,clock,probe=healthy).recover()
    store.billing_available=lambda:True
    after=command(repo,creds.client_id,'topup',1,clock.value)
    assert after['billing']['balance_kopecks']==60001
    assert len(operations(store,'purchase'))==1

async def test_failed_probe_replaces_previously_healthy_component(tmp_path):
    log=Diagnostics(tmp_path)
    for component in ('frp','gateway','npm'):log.component(component,'healthy')
    probe=ServiceProbe(SimpleNamespace(status=lambda:{'running':False}),SimpleNamespace(returncode=1),
        'https://tunnel.example.org',['127.0.0.1'],log)
    probe.last=False;probe.at=time.monotonic()
    assert await probe()==dict(frp=False,gateway=False,npm=False)
    assert all(log.snapshot()['components'][name]['state']=='unhealthy' for name in ('frp','gateway','npm'))

def test_unpaid_monthly_access_is_not_presented_as_unlimited(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    snap=command(repo,creds.client_id,'set_price',30000,now[0])
    assert format_metrics(None,snap,'Europe/Moscow')['access']=='не оплачен'
    free=command(repo,creds.client_id,'set_price',0,now[0])
    assert format_metrics(None,free,'Europe/Moscow')['access']=='бессрочный'
