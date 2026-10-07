import json
import sqlite3

import pytest

from server.app.store import Store, digest


def connected(tmp_path, now):
    store = Store(tmp_path/'state.db', 'example.org', clock=lambda: now[0])
    creds = store.redeem(store.issue('alpha', 1000).code, 1001)
    store.set_capabilities(creds.client_id, ['access-v1', 'telemetry-v1'])
    return store, creds


def test_legacy_migration_preserves_binding(tmp_path):
    path = tmp_path/'state.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE clients(id TEXT PRIMARY KEY, domain TEXT UNIQUE NOT NULL, code_hash TEXT UNIQUE, issued INTEGER NOT NULL, expires INTEGER NOT NULL, secret_hash TEXT, revoked INTEGER NOT NULL DEFAULT 0, last_seen INTEGER)')
        db.execute('INSERT INTO clients VALUES (?,?,?,?,?,?,?,?)', ('a'*32, 'alpha.example.org', None, 1000, 1900, digest('x'*43), 0, 1001))
        db.execute('INSERT INTO clients VALUES (?,?,?,?,?,?,?,?)', ('b'*32, 'bravo.example.org', None, 1000, 1900, None, 1, None))
    for _ in range(2):
        store = Store(path, 'example.org')
        assert store.authenticate('a'*32, 'x'*43)
        assert store.active('b'*32) is None
        snapshot = store.access_snapshot('a'*32, 2000)
        assert snapshot['deadline'] is None and not snapshot['paused']
        assert snapshot['generation'] == 0 and snapshot['to_client_bytes'] == 0
        assert store.status_authenticate('a'*32, 'x'*43)


def test_pause_start_preserves_deadline(tmp_path):
    now = [2000]
    store, creds = connected(tmp_path, now)
    ident = creds.client_id
    snap = store.apply_access(ident, 'set_duration', 'set-1', 0, now[0], {'minutes': 20})
    assert snap['deadline'] == 3200
    snap = store.apply_access(ident, 'pause', 'pause-1', snap['revision'], 2100)
    assert store.authenticate(ident, creds.secret) is None
    assert store.status_authenticate(ident, creds.secret)
    snap = store.apply_access(ident, 'start', 'start-1', snap['revision'], 2200)
    assert snap['deadline'] == 3200 and not snap['paused']
    now[0] = 3200
    assert store.active(ident) is None
    snap = store.apply_access(ident, 'start', 'start-2', snap['revision'], now[0])
    assert snap['deadline'] == 4400
    assert store.authenticate(ident, creds.secret)


def test_command_replay_after_store_restart(tmp_path):
    now = [2000]
    store, creds = connected(tmp_path, now)
    snap = store.apply_access(creds.client_id, 'set_duration', 'unique', 0, now[0], {'minutes': 20})
    store = Store(store.path, 'example.org', clock=lambda: now[0])
    replay = store.apply_access(creds.client_id, 'set_duration', 'unique', 0, 3000, {'minutes': 20})
    assert replay == snap
    with pytest.raises(ValueError):
        store.apply_access(creds.client_id, 'set_duration', 'unique', 0, 3000, {'minutes': 30})
    with pytest.raises(ValueError):
        store.apply_access(creds.client_id, 'pause', 'stale', 0, 3000)


def test_legacy_client_still_obeys_server_access_controls(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    creds = store.redeem(store.issue('alpha', 1000).code, 1001)
    result=store.apply_access(creds.client_id, 'pause', 'pause', 0, 2000)
    assert result['access_state']=='paused'
    assert store.authenticate(creds.client_id,creds.secret) is None
    store.revoke(creds.client_id)
    assert store.status_authenticate(creds.client_id, creds.secret)
    with pytest.raises(ValueError):
        store.apply_access(creds.client_id, 'start', 'start', 0, 2000)


def test_traffic_persists_without_secrets_in_snapshot(tmp_path):
    store, creds = connected(tmp_path, [2000])
    store.add_traffic(creds.client_id, 100, 200)
    store.add_traffic(creds.client_id, 5, 9)
    reopened = Store(store.path, 'example.org')
    snap = reopened.access_snapshot(creds.client_id, 2100)
    assert snap['to_client_bytes'] == 105 and snap['from_client_bytes'] == 209
    assert creds.secret not in json.dumps(snap)
    assert not any('hash' in k or 'secret' in k for k in snap)
    for pair in [(True, 1), (-1, 0), (1.0, 1)]:
        with pytest.raises(ValueError):
            store.add_traffic(creds.client_id, *pair)
