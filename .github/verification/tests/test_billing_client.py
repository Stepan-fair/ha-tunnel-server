import copy
from pathlib import Path
import pytest
from client.app.status import validate_status
from shared.presentation import format_billing
from tests.test_billing_store import funded, command, ZONE
from tests.test_subscription_calendar import stamp

def delivered(snapshot,now):
    data=copy.deepcopy(snapshot)
    data['billing']['updated_at']=now
    return data

def test_paid_and_funds_dates_are_inclusive(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    status=delivered(snap,now[0])
    validate_status(status,creds.client_id)
    p=format_billing(status['billing'])
    assert p['balance']=='600,00 ₽' and p['price']=='300,00 ₽ / месяц'
    assert p['paid']=='до 14.11.2026 включительно'
    assert p['funds']=='до 14.01.2027 включительно'
    assert 'Последние' in format_billing(status['billing'],stale=True)['updated']

def test_zero_price_and_manual_pause(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    snap=command(repo,creds.client_id,'set_price',0,now[0])
    snap=store.apply_access(creds.client_id,'pause','manual',snap['revision'],now[0])
    p=format_billing(delivered(snap,now[0])['billing'])
    assert p['paid']==p['funds']=='Бессрочно'
    assert 'ручная' in p['pause'].lower()

@pytest.mark.parametrize('field,value',[
    ('price_kopecks',True),('price_kopecks',1.5),('price_kopecks',-1),
    ('balance_kopecks',2**63),('paid_until',float('inf')),
    ('timezone','Invalid/Zone'),('pause_reason','secret'),('updated_at',True),
    ('projection_kind','x'*1000),('projection_kind',[]),('pause_reason',{}),('mode',[]),('secret','private'),('paid_from',stamp(2028,1,1)),
])
def test_invalid_financial_status_rejected(tmp_path,field,value):
    store,creds,repo,now,snap=funded(tmp_path)
    status=delivered(snap,now[0]);status['billing'][field]=value
    with pytest.raises(ValueError):validate_status(status,creds.client_id)

def test_old_server_missing_finance_remains_compatible():
    status=dict(client_id='a'*32,access_state='allowed',revision=0,generation=0)
    assert validate_status(status,'a'*32)==status
    assert format_billing(None)['available'] is False

def test_large_money_formatting_is_exact():
    data=dict(mode='monthly',price_kopecks=0,balance_kopecks=2**63-1,paid_from=None,paid_until=None,
        funds_until=None,projection_kind='unlimited',projection_limited=False,pause_reason=None,timezone=ZONE,updated_at=stamp(2026,10,15))
    assert format_billing(data)['balance']=='92233720368547758,07 ₽'

def test_client_has_readonly_financial_panel():
    html=Path('client/app/templates/index.html').read_text(encoding='utf-8')
    js=Path('client/app/templates/app.js').read_text(encoding='utf-8')
    assert 'billing' in html and 'billing_presentation' in js
    assert '/billing' not in js and 'innerHTML' not in js

async def test_client_cached_finance_is_stale_immediately_after_poll_failure(tmp_path,monkeypatch):
    from unittest.mock import AsyncMock
    import client.app.controller as module
    ctrl=module.Controller(tmp_path,tmp_path/'configuration.yaml',AsyncMock(),AsyncMock())
    ctrl.credentials=dict(client_id='a'*32,server_url='https://tunnel.example.org',secret='x'*43,domain='alpha.example.org')
    result=dict(client_id='a'*32,access_state='paused',revision=0,generation=0)
    service=AsyncMock()
    service.fetch.return_value=result
    monkeypatch.setattr(module,'ClientStatusClient',lambda url:service)
    await ctrl.poll_access()
    assert not ctrl.status()['billing_stale']
    service.fetch.side_effect=OSError('offline')
    with pytest.raises(OSError):await ctrl.poll_access()
    assert ctrl.status()['access']==result and ctrl.status()['billing_stale']
