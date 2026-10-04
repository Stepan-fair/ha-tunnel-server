import time
import pytest
from server.app.store import Store
from server.app.identity import Authority
from server.app.pki import ensure_pki


def test_encrypted_backup_restore_preserves_revocation_and_identity(tmp_path):
    from server.app.backup import export_state,restore_state
    state=tmp_path/'source'
    store=Store(state/'state.db','example.org')
    authority=Authority(state/'identity.key','http://127.0.0.1:19000')
    ensure_pki(state/'pki','tunnel.example.org')
    invite=store.issue('house',int(time.time()))
    credentials=store.redeem(invite.code,int(time.time()))
    store.revoke(credentials.client_id)
    blob=export_state(state,store,'a strong test password')
    assert b'PRIVATE KEY' not in blob and b'house.example.org' not in blob
    target=tmp_path/'target'
    Store(target/'state.db','example.org')
    restore_state(blob,'a strong test password',target,'example.org','tunnel.example.org')
    restored=Store(target/'state.db','example.org')
    assert restored.list_clients()[0]['revoked']==1
    assert restored.authenticate(credentials.client_id,credentials.secret) is None
    other=Authority(target/'identity.key','http://127.0.0.1:19000')
    with pytest.raises(ValueError): authority.subject(other.issue('a'*32))
    assert (target/'pki/ca.pem').read_bytes()==(state/'pki/ca.pem').read_bytes()


def test_restore_refuses_wrong_password_and_nonempty_server(tmp_path):
    from server.app.backup import export_state,restore_state
    state=tmp_path/'source'
    store=Store(state/'state.db','example.org')
    Authority(state/'identity.key','http://127.0.0.1:19000')
    ensure_pki(state/'pki','tunnel.example.org')
    blob=export_state(state,store,'a strong test password')
    target=tmp_path/'target'
    current=Store(target/'state.db','example.org')
    with pytest.raises(ValueError): restore_state(blob,'wrong password 12345',target,'example.org','tunnel.example.org')
    current.issue('existing',int(time.time()))
    before=(target/'state.db').read_bytes()
    with pytest.raises(ValueError): restore_state(blob,'a strong test password',target,'example.org','tunnel.example.org')
    assert before==(target/'state.db').read_bytes()


def test_restore_refuses_domain_now_used_by_registration_server(tmp_path):
    from server.app.backup import export_state,restore_state
    state=tmp_path/'source'
    store=Store(state/'state.db','example.org')
    Authority(state/'identity.key','http://127.0.0.1:19000')
    ensure_pki(state/'pki','tunnel.example.org')
    store.issue('connect',0)
    blob=export_state(state,store,'a strong test password')
    target=tmp_path/'target'
    with pytest.raises(ValueError):
        restore_state(blob,'a strong test password',target,'example.org','connect.example.org')
    assert not Store(target/'state.db','example.org').list_clients()
    assert not target.with_name('target.pre-restore').exists()
