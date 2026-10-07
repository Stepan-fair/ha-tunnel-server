import time
import pytest

from server.app.store import Store


def test_pending_code_can_be_revealed_until_redeem(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    invite = store.issue('alpha', 1000)
    assert store.show_code(invite.client_id, 1001).code == invite.code
    assert store.show_code(invite.client_id, 1002).code == invite.code
    assert invite.code.encode() not in store.path.read_bytes()
    store.redeem(invite.code, 1003)
    with pytest.raises(ValueError):
        store.show_code(invite.client_id, 1004)


def test_reissue_keeps_old_access_until_redeemed(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org', clock=lambda: 2000)
    creds = store.redeem(store.issue('alpha', 1000).code, 1001)
    store.set_capabilities(creds.client_id, ['access-v1'])
    store.apply_access(creds.client_id, 'set_duration', 'one', 0, 2000, {'hours': 1})
    store.add_traffic(creds.client_id, 17, 29)
    invite = store.reissue(creds.client_id, 2000)
    assert store.authenticate(creds.client_id, creds.secret)
    newer = store.redeem(invite.code, 2001)
    assert newer.client_id == creds.client_id and newer.domain == creds.domain
    assert store.authenticate(creds.client_id, creds.secret) is None
    assert store.status_authenticate(creds.client_id, creds.secret) is None
    assert store.authenticate(newer.client_id, newer.secret)
    snap = store.access_snapshot(creds.client_id, 2002)
    assert snap['generation'] == 1 and snap['deadline'] == 5600
    assert snap['to_client_bytes'] == 17 and snap['from_client_bytes'] == 29
    with pytest.raises(ValueError):
        store.redeem(invite.code, 2002)


def test_missing_invitation_key_fails_without_replacement(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    invite = store.issue('alpha', 1000)
    key = tmp_path/'invitations.key'
    key.unlink()
    reopened = Store(store.path, 'example.org')
    with pytest.raises(ValueError):
        reopened.show_code(invite.client_id, 1001)
    assert not key.exists()
    with pytest.raises(ValueError):
        reopened.issue('bravo', 1001)
    assert not key.exists()


def test_backup_preserves_history_but_invalidates_authorization(tmp_path):
    from server.app.backup import export_state, restore_state
    from server.app.identity import Authority
    from server.app.pki import ensure_pki
    source, dest = tmp_path/'source', tmp_path/'dest'
    store = Store(source/'state.db', 'example.org')
    Authority(source/'identity.key', 'http://127.0.0.1:19000')
    ensure_pki(source/'pki', 'tunnel.example.org')
    now = int(time.time())
    credentials = store.redeem(store.issue('alpha', now).code, now)
    store.set_capabilities(credentials.client_id, ['access-v1'])
    store.apply_access(credentials.client_id, 'set_duration', 'period', 0, now, {'hours': 1})
    store.add_traffic(credentials.client_id, 100, 200)
    invite = store.reissue(credentials.client_id, now)
    blob = export_state(source, store, 'a strong test password')
    assert blob.startswith(b'HATB3')
    restore_state(blob, 'a strong test password', dest, 'example.org', 'tunnel.example.org')
    restored = Store(dest/'state.db', 'example.org')
    previous=store.access_snapshot(credentials.client_id,now)
    result=restored.access_snapshot(credentials.client_id,now)
    for field in ('duration','deadline','to_client_bytes','from_client_bytes','traffic_started_at','domain'):
        assert result[field]==previous[field]
    assert result['revoked'] and result['generation']==previous['generation']+1
    assert restored.authenticate(credentials.client_id,credentials.secret) is None
    with pytest.raises(ValueError): restored.show_code(credentials.client_id,now)
    assert restored.get_metadata('instance_id') == store.get_metadata('instance_id')


def test_original_backup_format_remains_readable(tmp_path):
    import base64
    import json
    import secrets
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from server.app.backup import COLUMNS, FILES, key, restore_state
    from server.app.identity import Authority
    from server.app.pki import ensure_pki
    source, dest = tmp_path/'source', tmp_path/'dest'
    store = Store(source/'state.db', 'example.org')
    Authority(source/'identity.key', 'http://127.0.0.1:19000')
    ensure_pki(source/'pki', 'tunnel.example.org')
    credentials = store.redeem(store.issue('alpha', 1000).code, 1001)
    with store.connection() as db:
        rows = [dict(row) for row in db.execute('SELECT '+','.join(COLUMNS)+' FROM clients')]
    payload = {'version': 1, 'base_domain': 'example.org', 'clients': rows,
               'files': {name: base64.b64encode((source/name).read_bytes()).decode() for name in FILES}}
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    password = 'a strong test password'
    blob = b'HATB1'+salt+nonce+AESGCM(key(password, salt)).encrypt(nonce, json.dumps(payload).encode(), b'HATB1')
    restore_state(blob, password, dest, 'example.org', 'tunnel.example.org')
    restored = Store(dest/'state.db', 'example.org')
    assert restored.authenticate(credentials.client_id, credentials.secret) is None
    assert restored.status_authenticate(credentials.client_id, credentials.secret) is None
    assert restored.access_snapshot(credentials.client_id, 1002)['access_state'] == 'revoked'
