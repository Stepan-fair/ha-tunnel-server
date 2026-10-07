import asyncio
import copy
from pathlib import Path
import pytest
from server.app.domain_migration import DomainMigration
from server.app.setup import SetupService
from server.app.store import Store,ConflictError
from tests.test_billing_store import funded,command,operations,ZONE
from server.app.identity import Authority
from server.app.pki import ensure_pki

class Supervisor:
    def __init__(self,options):self.options=copy.deepcopy(options);self.posts=0;self.fail=False
    async def get(self,path):return {'options':copy.deepcopy(self.options)}
    async def post(self,path,body):
        if self.fail:raise OSError('failed')
        self.options=copy.deepcopy(body['options']);self.posts+=1
class Access:
    def __init__(self):self.closed=False
    async def quiesce(self):self.closed=True
async def ready(draft):return dict(dns=True,tls=True,wildcard=True,ready=True)

def context(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path/'state')
    old=dict(base_domain='example.org',server_url='https://tunnel.example.org',npm_host='npm',
        admin_user_ids=['admin'],reserved_names=[],bandwidth_limit_mb=10)
    setup=SetupService(tmp_path,Supervisor(old));setup.options=old
    migration=DomainMigration(store,setup,Access(),readiness=ready)
    draft={**old,'base_domain':'example.net','server_url':'https://tunnel.example.net'}
    return store,creds,repo,now,snap,setup,migration,draft

async def test_move_preserves_finance_and_manual_pause_invalidates_credentials(tmp_path):
    store,creds,repo,now,snap,setup,migration,draft=context(tmp_path)
    snap=store.apply_access(creds.client_id,'pause','pause',snap['revision'],now[0])
    old=store.reissue(creds.client_id,int(now[0]))
    preview=await migration.preview(draft)
    assert preview['clients'][0]['new_domain']=='alpha.example.net'
    result=await migration.apply(draft,'move',preview['revision'])
    assert migration.access.closed and result['phase']=='committed'
    assert await migration.apply(draft,'move',preview['revision'])==result
    reopened=Store(store.path,'example.net',clock=lambda:now[0])
    moved=reopened.access_snapshot(creds.client_id,now[0])
    assert moved['domain']=='alpha.example.net' and moved['paused']
    for field in ('price_kopecks','balance_kopecks','paid_from','paid_until','timezone'):
        assert moved['billing'][field]==snap['billing'][field]
    assert moved['billing']['pause_reason']=='pending'
    assert moved['generation']>snap['generation']
    assert not reopened.authenticate(creds.client_id,creds.secret)
    assert not reopened.status_authenticate(creds.client_id,creds.secret)
    with pytest.raises(ValueError):reopened.redeem(old.code,int(now[0]))
    reopened.redeem(reopened.reissue(creds.client_id,int(now[0])).code,int(now[0]))
    assert len(operations(reopened,'purchase'))==1

async def test_revoked_remains_revoked_and_collision_or_stale_cannot_write(tmp_path):
    store,creds,repo,now,snap,setup,migration,draft=context(tmp_path)
    preview=await migration.preview(draft)
    command(repo,creds.client_id,'topup',1,now[0])
    with pytest.raises(ConflictError):await migration.apply(draft,'stale',preview['revision'])
    assert setup.supervisor.posts==0
    conflict={**draft,'reserved_names':['alpha']}
    with pytest.raises(ValueError):await migration.preview(conflict)
    invalid={**draft,'server_url':'https://other.invalid'}
    with pytest.raises(ValueError):await migration.preview(invalid)
    store.revoke(creds.client_id)
    preview=await migration.preview(draft);await migration.apply(draft,'good',preview['revision'])
    assert Store(store.path,'example.net').access_snapshot(creds.client_id,now[0])['revoked']

@pytest.mark.parametrize('phase',['prepared','options_saved','committed'])
async def test_fault_phase_recovers_without_mixed_live_identity(tmp_path,monkeypatch,phase):
    store,creds,repo,now,snap,setup,migration,draft=context(tmp_path)
    preview=await migration.preview(draft)
    original=migration._save_marker
    def fail(marker):
        original(marker)
        if marker['phase']==phase:raise RuntimeError('simulated interruption')
    monkeypatch.setattr(migration,'_save_marker',fail)
    with pytest.raises(RuntimeError):await migration.apply(draft,'fault',preview['revision'])
    assert store.migrating
    recovered=DomainMigration(store,setup,None,readiness=ready)
    await recovered.recover()
    expected='example.org' if phase=='prepared' else 'example.net'
    current=Store(store.path,expected,clock=lambda:now[0])
    assert current.list_clients()[0]['domain']=='alpha.'+expected
    assert len(operations(current,'purchase'))==1

async def test_option_write_failure_rolls_back_and_pki_keeps_ca(tmp_path):
    store,creds,repo,now,snap,setup,migration,draft=context(tmp_path)
    setup.supervisor.fail=True
    preview=await migration.preview(draft)
    with pytest.raises(OSError):await migration.apply(draft,'fail',preview['revision'])
    await DomainMigration(store,setup,None,readiness=ready).recover()
    assert Store(store.path,'example.org').list_clients()[0]['domain']=='alpha.example.org'
    pki=ensure_pki(tmp_path/'pki','tunnel.example.org');ca=pki.ca.read_bytes()
    renewed=ensure_pki(tmp_path/'pki','tunnel.example.net')
    assert renewed.ca.read_bytes()==ca and renewed.renewed
