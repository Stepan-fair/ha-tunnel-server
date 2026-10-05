import json
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from server.app.backup import export_state,restore_state,key
from server.app.identity import Authority
from server.app.pki import ensure_pki
from server.app.store import Store
from server.app.availability import AvailabilityService
from tests.test_availability import Clock,healthy
from tests.test_billing_store import funded,operations,command,ZONE

PASSWORD='a strong test password'
def package(store):
    Authority(store.path.parent/'identity.key','http://127.0.0.1:19000')
    ensure_pki(store.path.parent/'pki','tunnel.example.org')
    return export_state(store.path.parent,store,PASSWORD)

def modify(blob,callback):
    header,salt,nonce=blob[:5],blob[5:21],blob[21:33]
    payload=json.loads(AESGCM(key(PASSWORD,salt)).decrypt(nonce,blob[33:],header))
    callback(payload)
    return header+salt+nonce+AESGCM(key(PASSWORD,salt)).encrypt(nonce,json.dumps(payload).encode(),header)

async def test_outage_backup_preserves_completed_history_not_portable_age(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path/'source')
    clock=Clock(now[0]);store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy)
    await service.recover()
    clock.value+=37*3600
    await AvailabilityService(store,clock,probe=healthy).recover()
    bought=store.access_snapshot(creds.client_id,clock.value)['billing']['paid_until']
    blob=package(store)
    target=tmp_path/'target'
    restore_state(blob,PASSWORD,target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org',clock=clock)
    assert len(operations(restored,'compensation'))==1
    await AvailabilityService(restored,clock,probe=healthy).recover()
    assert restored.access_snapshot(creds.client_id,clock.value)['billing']['paid_until']==bought
    with restored.connection() as db:assert db.execute("select count(*) from outage_episodes where state='closed'").fetchone()[0]>=1

def test_delete_retains_ledger_and_backup_valid(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path/'source')
    store.revoke(creds.client_id)
    store.delete_revoked(creds.client_id,store.access_snapshot(creds.client_id,now[0])['revision'])
    assert len(operations(store,'purchase'))==1
    target=tmp_path/'target'
    restore_state(package(store),PASSWORD,target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org')
    assert len(operations(restored,'purchase'))==1 and not restored.list_clients()

@pytest.mark.parametrize('kind',['price','period','command_client','command_secret','command_nested','schema','timezone'])
def test_malformed_financial_backup_never_replaces_live_folder(tmp_path,kind):
    store,creds,repo,now,snap=funded(tmp_path/'source')
    blob=package(store)
    def corrupt(p):
        if kind=='price':p['clients'][0]['price_kopecks']=True
        if kind=='period':p['clients'][0]['paid_from']=p['clients'][0]['paid_until']+1
        if kind=='command_client':p['billing_commands'][0]['client_id']='b'*32
        if kind in ('command_secret','command_nested'):
            result=json.loads(p['billing_commands'][0]['result'])
            if kind=='command_secret': result['secret']='PRIVATE'
            else:result['billing']['secret']='PRIVATE'
            p['billing_commands'][0]['result']=json.dumps(result)
        if kind=='schema':p['version']=99
        if kind=='timezone':p['clients'][0]['billing_timezone']='Invalid/Zone'
    target=tmp_path/'target'; empty=Store(target/'state.db','example.org')
    before=(target/'state.db').read_bytes()
    with pytest.raises(ValueError):restore_state(modify(blob,corrupt),PASSWORD,target,'example.org','tunnel.example.org')
    assert (target/'state.db').read_bytes()==before
    assert not target.with_name('target.pre-restore').exists()

def test_paid_manual_pause_restore_reenroll_never_spends_again(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path/'source')
    store.apply_access(creds.client_id,'pause','pause',snap['revision'],now[0])
    target=tmp_path/'target';restore_state(package(store),PASSWORD,target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org',clock=lambda:now[0])
    restored.redeem(restored.reissue(creds.client_id,int(now[0])).code,int(now[0]))
    after=restored.access_snapshot(creds.client_id,now[0])
    assert after['paused'] and after['billing']['balance_kopecks']==60000
    assert len(operations(restored,'purchase'))==1

async def test_open_outage_import_is_handled_without_compensation(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path/'source')
    clock=Clock(now[0]);store.clock=clock
    service=AvailabilityService(store,clock,probe=healthy)
    await service.recover();await service.shutdown()
    target=tmp_path/'target'
    restore_state(package(store),PASSWORD,target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org',clock=clock)
    clock.value+=100*86400
    await AvailabilityService(restored,clock,probe=healthy).recover()
    assert not operations(restored,'compensation')
    with restored.connection() as db: assert db.execute("select count(*) from outage_episodes where state='imported'").fetchone()[0]==1

def test_interrupted_staged_rename_rolls_back_empty_destination(tmp_path,monkeypatch):
    from pathlib import Path
    store,creds,repo,now,snap=funded(tmp_path/'source')
    blob=package(store);target=tmp_path/'target';Store(target/'state.db','example.org')
    before=(target/'state.db').read_bytes()
    original=Path.rename
    def rename(source,destination):
        if source.name=='state' and '.restore-' in str(source.parent): raise OSError('simulated rename failure')
        return original(source,destination)
    monkeypatch.setattr(Path,'rename',rename)
    with pytest.raises(OSError):restore_state(blob,PASSWORD,target,'example.org','tunnel.example.org')
    assert (target/'state.db').read_bytes()==before and not target.with_name('target.pre-restore').exists()
