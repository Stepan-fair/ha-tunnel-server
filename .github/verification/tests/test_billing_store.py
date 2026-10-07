import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from server.app.store import Store, ConflictError
from server.app.billing import BillingRepository
from server.app.subscription import MAX_MONEY
from tests.test_subscription_calendar import stamp

ZONE='Europe/Moscow'


def connected(tmp_path,now=None):
    now=now or [stamp(2026,10,15,10)]
    store=Store(tmp_path/'state.db','example.org',clock=lambda:now[0])
    credential=store.redeem(store.issue('alpha',int(now[0])).code,int(now[0]))
    return store,credential,BillingRepository(store),now


def command(repo,cid,action,value,now,key=None):
    snap=repo.store.access_snapshot(cid,now)
    return repo.command(cid,action,key or action+str(snap['revision']),snap['revision'],
        value_kopecks=value,now=now,timezone=ZONE)


def operations(store,kind=None):
    with store.connection() as db:
        return [dict(r) for r in db.execute('select * from billing_operations'+(' where kind=?' if kind else ''),(kind,) if kind else ())]


def funded(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    command(repo,creds.client_id,'set_price',30000,now[0])
    snap=command(repo,creds.client_id,'topup',90000,now[0])
    return store,creds,repo,now,snap


def test_topup_900_buys_one_300_month(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    assert snap['billing']['balance_kopecks']==60000
    assert snap['billing']['paid_until']==stamp(2026,11,15)
    assert snap['access_state']=='allowed' and len(operations(store,'purchase'))==1
    now[0]=stamp(2026,11,15)
    snap=repo.reconcile(creds.client_id,now[0],timezone=ZONE)
    assert snap['billing']['balance_kopecks']==30000
    assert snap['billing']['paid_until']==stamp(2026,12,15)
    assert len(operations(store,'purchase'))==2


def test_restart_replay_and_two_connections(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    command(repo,creds.client_id,'set_price',30000,now[0])
    rev=store.access_snapshot(creds.client_id,now[0])['revision']
    result=repo.command(creds.client_id,'topup','same',rev,value_kopecks=30000,now=now[0],timezone=ZONE)
    reopened=Store(store.path,'example.org',clock=lambda:now[0])
    again=BillingRepository(reopened).command(creds.client_id,'topup','same',rev,value_kopecks=30000,now=now[0],timezone=ZONE)
    assert again==result and len(operations(store,'purchase'))==1
    with pytest.raises(ValueError):
        BillingRepository(reopened).command(creds.client_id,'topup','same',rev,value_kopecks=60000,now=now[0],timezone=ZONE)
    command(repo,creds.client_id,'topup',30000,now[0])
    now[0]=stamp(2026,11,15)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda s:BillingRepository(s).reconcile(creds.client_id,now[0],timezone=ZONE),[store,reopened]))
    assert all(r['billing']['balance_kopecks']==0 for r in results)
    assert len(operations(store,'purchase'))==2


def test_debit_atomic_under_failure(tmp_path,monkeypatch):
    import server.app.billing as billing
    store,creds,repo,now=connected(tmp_path)
    command(repo,creds.client_id,'set_price',30000,now[0])
    before=store.access_snapshot(creds.client_id,now[0])
    def fail(*args,**kwargs): raise sqlite3.OperationalError('simulated disk failure')
    monkeypatch.setattr(billing,'append_event',fail)
    with pytest.raises(sqlite3.Error):
        command(repo,creds.client_id,'topup',30000,now[0])
    assert store.access_snapshot(creds.client_id,now[0])==before
    assert len(operations(store,'purchase'))==0


def test_manual_pause_blocks_purchase_and_topup_start(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    command(repo,creds.client_id,'set_price',30000,now[0])
    snap=store.access_snapshot(creds.client_id,now[0])
    store.apply_access(creds.client_id,'pause','pause',snap['revision'],now[0])
    snap=command(repo,creds.client_id,'topup',30000,now[0])
    assert snap['paused'] and snap['billing']['balance_kopecks']==30000
    assert not operations(store,'purchase')
    store.apply_access(creds.client_id,'start','start',snap['revision'],now[0])
    snap=repo.reconcile(creds.client_id,now[0],timezone=ZONE)
    assert snap['billing']['balance_kopecks']==0 and snap['access_state']=='allowed'


def test_late_topup_restarts_from_payment_date(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    command(repo,creds.client_id,'set_balance',0,now[0])
    now[0]=stamp(2026,11,15)
    assert repo.reconcile(creds.client_id,now[0],timezone=ZONE)['access_state']=='expired'
    now[0]=stamp(2026,11,20,14)
    snap=command(repo,creds.client_id,'topup',30000,now[0])
    assert snap['billing']['paid_from']==now[0]
    assert snap['billing']['paid_until']==stamp(2026,12,20)


def test_price_change_only_affects_next_month(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    changed=command(repo,creds.client_id,'set_price',40000,now[0])
    assert changed['billing']['paid_until']==snap['billing']['paid_until']
    assert changed['billing']['balance_kopecks']==60000
    now[0]=stamp(2026,11,15)
    renewed=repo.reconcile(creds.client_id,now[0],timezone=ZONE)
    assert renewed['billing']['balance_kopecks']==20000


def test_price_zero_ignores_debt_but_not_manual_pause(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    command(repo,creds.client_id,'set_balance',-10000,now[0])
    snap=command(repo,creds.client_id,'set_price',0,now[0])
    now[0]=stamp(2030,11,15)
    assert store.access_snapshot(creds.client_id,now[0])['access_state']=='allowed'
    assert snap['billing']['projection_kind']=='unlimited' and snap['deadline'] is None
    store.apply_access(creds.client_id,'pause','p',snap['revision'],now[0])
    snap=command(repo,creds.client_id,'topup',30000,now[0])
    assert snap['access_state']=='paused' and len(operations(store,'purchase'))==1


def test_pending_client_can_receive_funds_without_purchase(tmp_path):
    now=stamp(2026,10,15,10)
    store=Store(tmp_path/'state.db','example.org',clock=lambda:now)
    invite=store.issue('pending',int(now))
    repo=BillingRepository(store)
    command(repo,invite.client_id,'set_price',30000,now)
    snap=command(repo,invite.client_id,'topup',30000,now)
    assert snap['access_state']=='pending' and not operations(store,'purchase')


@pytest.mark.parametrize('value',[True,1.0,-1,2**63])
def test_invalid_price_is_rejected(tmp_path,value):
    store,creds,repo,now=connected(tmp_path)
    with pytest.raises(ValueError): command(repo,creds.client_id,'set_price',value,now[0])
    assert not operations(store)


def test_stale_revision_and_overflow_are_rejected(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    command(repo,creds.client_id,'set_balance',MAX_MONEY,now[0])
    with pytest.raises(ValueError): command(repo,creds.client_id,'topup',1,now[0])
    with pytest.raises(ConflictError):
        repo.command(creds.client_id,'set_price','stale',0,value_kopecks=30000,now=now[0],timezone=ZONE)
    assert store.access_snapshot(creds.client_id,now[0])['billing']['balance_kopecks']==MAX_MONEY


def test_explicit_subscription_cannot_use_legacy_duration(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    snap=command(repo,creds.client_id,'set_price',30000,now[0])
    for action in ('permanent','set_duration'):
        with pytest.raises(ConflictError):
            store.apply_access(creds.client_id,action,action,snap['revision'],now[0],{'months':1},ZONE)


def test_legacy_timed_stays_legacy_and_upgrade_preserves_pause(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    snap=store.apply_access(creds.client_id,'set_duration','timed',0,now[0],{'minutes':20},ZONE)
    paused=store.apply_access(creds.client_id,'pause','pause',snap['revision'],now[0])
    with store.connection() as db: db.execute('PRAGMA user_version=3')
    reopened=Store(store.path,'example.org',clock=lambda:now[0])
    result=reopened.access_snapshot(creds.client_id,now[0])
    assert result['billing']['mode']=='legacy' and result['deadline']==paused['deadline'] and result['paused']
    assert reopened.status_authenticate(creds.client_id,creds.secret)
    assert BillingRepository(reopened).reconcile(creds.client_id,now[0],timezone=ZONE)==result


def test_clock_error_does_not_spend(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    class BadClock:
        reliable=False
        def now(self): return now[0]
    store.clock=BadClock()
    with pytest.raises(ConflictError): command(repo,creds.client_id,'set_price',30000,now[0])
    assert not operations(store)


def test_financial_backup_uses_new_format_and_preserves_money(tmp_path):
    from server.app.backup import export_state,restore_state
    from server.app.identity import Authority
    from server.app.pki import ensure_pki
    store,creds,repo,now,snap=funded(tmp_path/'source')
    Authority(store.path.parent/'identity.key','http://localhost')
    ensure_pki(store.path.parent/'pki','tunnel.example.org')
    blob=export_state(store.path.parent,store,'a strong test password')
    assert blob[:5]==b'HATB4'
    target=tmp_path/'restored'
    restore_state(blob,'a strong test password',target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org',clock=lambda:now[0])
    state=restored.access_snapshot(creds.client_id,now[0])
    assert state['billing']['balance_kopecks']==60000 and state['billing']['paid_until']==snap['billing']['paid_until']
    assert len(operations(restored,'purchase'))==1 and state['revoked']
    assert not restored.authenticate(creds.client_id,creds.secret)


def test_exact_balance_change_checks_ledger_delta_before_write(tmp_path):
    store,creds,repo,now=connected(tmp_path)
    before=command(repo,creds.client_id,'set_balance',-(2**63),now[0])
    with pytest.raises(ValueError):
        command(repo,creds.client_id,'set_balance',2**63-1,now[0])
    assert store.access_snapshot(creds.client_id,now[0])==before


def test_topup_after_gap_without_an_expiry_tick_starts_today(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    command(repo,creds.client_id,'set_balance',0,now[0])
    now[0]=stamp(2026,11,20,14)
    result=command(repo,creds.client_id,'topup',30000,now[0])
    assert result['billing']['paid_from']==now[0] and result['billing']['paid_until']==stamp(2026,12,20)
