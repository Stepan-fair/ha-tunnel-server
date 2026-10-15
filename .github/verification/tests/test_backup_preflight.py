import json
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from server.app.store import Store,ConflictError
from server.app.backup import export_state,restore_state,key
from tests.test_billing_backup import package,PASSWORD
from tests.test_billing_store import funded,operations,command


def test_h5_preview_truthful_date_inventory_and_authentication(tmp_path):
    from server.app.backup import backup_preview
    store,c,repo,now,snap=funded(tmp_path/'source')
    blob=package(store)
    preview=backup_preview(blob,PASSWORD)
    assert blob[:5]==b'HATB5' and preview['format']=='HATB5'
    assert preview['created_at']==now[0]
    assert preview['inventory']['clients']==1 and preview['inventory']['billing_operations']==3
    assert len(preview['digest'])==64
    with pytest.raises(ValueError): backup_preview(blob,'incorrect password 123')
    class Clock:
        reliable=False
        def now(self): return now[0]
    store.clock=Clock()
    with pytest.raises(ValueError): package(store)


@pytest.mark.parametrize('kind',['ledger','commands','migration'])
def test_restore_refuses_financially_nonempty_clients_empty_destination(tmp_path,kind):
    source=Store(tmp_path/'source/state.db','example.org')
    blob=package(source)
    target=tmp_path/'target'; current=Store(target/'state.db','example.org')
    with current.connection() as db:
        if kind=='ledger':
            db.execute("INSERT INTO billing_operations VALUES ('history',?, 'topup',2000,1,0,1,0,NULL,NULL,'{}','{}')",('a'*32,))
        elif kind=='commands': db.execute("INSERT INTO billing_commands VALUES (?, 'old','[]','{}')",('a'*32,))
        else: db.execute("INSERT INTO server_metadata VALUES ('domain_migration','{\"phase\":\"prepared\"}')")
    before=current.path.read_bytes()
    with pytest.raises(ValueError): restore_state(blob,PASSWORD,target,'example.org','tunnel.example.org')
    assert current.path.read_bytes()==before and not target.with_name('target.pre-restore').exists()


def test_restore_revision_ignores_technical_audit_but_detects_business_change(tmp_path):
    from server.app.backup import restore_revision,validate_restore_confirmation,backup_preview
    from server.app.journal import Journal
    source=Store(tmp_path/'source/state.db','example.org');blob=package(source)
    current=Store(tmp_path/'target/state.db','example.org')
    preview=backup_preview(blob,PASSWORD); revision=restore_revision(current)
    Journal(current).record('backup_restore',current.now())
    validate_restore_confirmation(current,blob,PASSWORD,preview['digest'],revision)
    current.issue('later',2000)
    with pytest.raises(ConflictError): validate_restore_confirmation(current,blob,PASSWORD,preview['digest'],revision)


def test_old_backup_unknown_date_requires_explicit_confirmation(tmp_path):
    from server.app.backup import backup_preview,restore_revision,validate_restore_confirmation
    source=Store(tmp_path/'source/state.db','example.org');blob=package(source)
    salt,nonce=blob[5:21],blob[21:33]
    payload=json.loads(AESGCM(key(PASSWORD,salt)).decrypt(nonce,blob[33:],blob[:5]))
    payload.pop('created_at',None);payload['version']=4
    old=b'HATB4'+salt+nonce+AESGCM(key(PASSWORD,salt)).encrypt(nonce,json.dumps(payload).encode(),b'HATB4')
    preview=backup_preview(old,PASSWORD)
    assert preview['created_at'] is None and preview['format']=='HATB4'
    current=Store(tmp_path/'target/state.db','example.org');rev=restore_revision(current)
    with pytest.raises(ValueError): validate_restore_confirmation(current,old,PASSWORD,preview['digest'],rev)
    validate_restore_confirmation(current,old,PASSWORD,preview['digest'],rev,confirm_unknown_date=True)
    with pytest.raises(ConflictError): validate_restore_confirmation(current,blob,PASSWORD,preview['digest'],rev,confirm_unknown_date=True)


def test_paid_expired_delete_export_fresh_restore_preserves_ledger(tmp_path):
    store,c,repo,now,snap=funded(tmp_path/'source')
    store.revoke(c.client_id)
    command(repo,c.client_id,'set_balance',0,now[0])
    now[0]=snap['billing']['paid_until']+1
    history=operations(store)
    store.delete_revoked(c.client_id,store.access_snapshot(c.client_id,now[0])['revision'])
    target=tmp_path/'target'
    restore_state(package(store),PASSWORD,target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org')
    assert operations(restored)==history and not restored.list_clients()



def test_restore_rechecks_destination_after_staging_before_swap(tmp_path,monkeypatch):
    import server.app.backup as backup
    source=Store(tmp_path/'source/state.db','example.org');blob=package(source)
    current=Store(tmp_path/'target/state.db','example.org')
    original=backup.ensure_pki
    def mutate_while_staging(*args,**kwargs):
        original(*args,**kwargs)
        with current.connection() as db:
            db.execute("INSERT INTO billing_commands VALUES (?, 'late','[]','{}')",('a'*32,))
    monkeypatch.setattr(backup,'ensure_pki',mutate_while_staging)
    with pytest.raises(ValueError):restore_state(blob,PASSWORD,current.path.parent,'example.org','tunnel.example.org')
    with current.connection() as db: assert db.execute('SELECT COUNT(*) FROM billing_commands').fetchone()[0]==1
    assert not current.path.parent.with_name('target.pre-restore').exists()

@pytest.mark.parametrize('version',[1,2,3,4])
def test_historical_formats_preview_unknown_date_and_restore_authority_closed(tmp_path,version):
    from server.app.backup import backup_preview,COLUMNS
    from server.app.migrations import BILLING_COLUMNS
    store=Store(tmp_path/'source/state.db','example.org',clock=lambda:2000)
    creds=store.redeem(store.issue('alpha',2000).code,2000)
    blob=package(store);salt,nonce=blob[5:21],blob[21:33]
    payload=json.loads(AESGCM(key(PASSWORD,salt)).decrypt(nonce,blob[33:],blob[:5]))
    payload.pop('created_at');payload['version']=version
    if version<4:
        for field in ('billing_operations','billing_commands','availability'): payload.pop(field)
        for row in payload['clients']:
            for field in BILLING_COLUMNS: row.pop(field)
    if version<3: payload.pop('audit')
    if version<2:
        payload.pop('metadata');payload.pop('commands');payload['files'].pop('invitations.key',None)
        payload['clients']=[{name:row[name] for name in COLUMNS} for row in payload['clients']]
    header=('HATB'+str(version)).encode()
    old=header+salt+nonce+AESGCM(key(PASSWORD,salt)).encrypt(nonce,json.dumps(payload).encode(),header)
    assert backup_preview(old,PASSWORD)['created_at'] is None
    target=tmp_path/'target';restore_state(old,PASSWORD,target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org',clock=lambda:2000)
    assert restored.list_clients()[0]['revoked']
    assert restored.authenticate(creds.client_id,creds.secret) is None


def test_portable_copy_never_contains_plaintext_invitation_command_result(tmp_path):
    store=Store(tmp_path/'source/state.db','example.org',clock=lambda:2000)
    creds=store.redeem(store.issue('alpha',2000).code,2000)
    invite=store.reissue(creds.client_id,2000,command_id='invitation',expected_revision=0)
    blob=package(store)
    raw=AESGCM(key(PASSWORD,blob[5:21])).decrypt(blob[21:33],blob[33:],blob[:5])
    assert invite.code.encode() not in raw and creds.secret.encode() not in raw
