import csv
import io
import sqlite3

import pytest

from server.app.store import Store


def connected(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org', clock=lambda: 2000)
    creds = store.redeem(store.issue('alpha', 1000).code, 1001)
    store.set_capabilities(creds.client_id, ['access-v1'])
    return store, creds


def journal(store):
    from server.app.journal import Journal
    return Journal(store)


def test_journal_survives_reopen(tmp_path):
    store, creds = connected(tmp_path)
    store.apply_access(creds.client_id, 'pause', 'pause', 0, 2000)
    reopened = Store(store.path, 'example.org')
    rows = journal(reopened).page(client_id=creds.client_id)['items']
    assert [r['action'] for r in rows] == ['pause', 'redeem', 'issue']
    assert rows[0]['at'] == 2000 and rows[0]['domain'] == 'alpha.example.org'


def test_duplicate_command_has_one_success(tmp_path):
    store, creds = connected(tmp_path)
    for now in (2000, 2001):
        store.apply_access(creds.client_id, 'pause', 'same', 0, now)
    assert len(journal(store).page(action='pause')['items']) == 1


def test_command_and_audit_commit_together(tmp_path):
    store, creds = connected(tmp_path)
    with store.connection() as db:
        db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events WHEN NEW.action='pause' BEGIN SELECT RAISE(ABORT,'full'); END")
    with pytest.raises(sqlite3.DatabaseError):
        store.apply_access(creds.client_id, 'pause', 'pause', 0, 2000)
    snap = store.access_snapshot(creds.client_id, 2000)
    assert not snap['paused'] and snap['revision'] == 0


def test_journal_filters_and_cursor(tmp_path):
    store, creds = connected(tmp_path)
    store.apply_access(creds.client_id, 'pause', 'pause', 0, 2000)
    first = journal(store).page(limit=2)
    second = journal(store).page(limit=2, before_id=first['next_cursor'])
    assert len(first['items']) == 2 and second['items']
    assert not {r['id'] for r in first['items']} & {r['id'] for r in second['items']}
    assert len(journal(store).page(since=2000, until=2000)['items']) == 1
    with pytest.raises(ValueError): journal(store).page(limit=101)


def test_csv_formula_and_secret_redaction(tmp_path):
    from server.app.journal import Actor, append_event
    store, creds = connected(tmp_path)
    with store.connection() as db:
        append_event(db, action='pause', actor=Actor('web', '=evil'), client_id=creds.client_id,
                     domain='alpha.example.org', result='success', at=2000,
                     details={'secret': creds.secret, 'invitation': 'private', 'deadline': 2500})
    exported = ''.join(journal(store).csv({}))
    assert creds.secret not in exported and 'private' not in exported
    assert "'=evil" in exported
    rows = list(csv.reader(io.StringIO(exported)))
    assert rows[0][0] == 'ID' and len(rows) >= 4


def test_expiry_logs_once(tmp_path):
    store, creds = connected(tmp_path)
    store.apply_access(creds.client_id, 'set_duration', 'duration', 0, 2000, {'minutes': 1})
    assert store.record_expiry(creds.client_id, 2060)
    assert not store.record_expiry(creds.client_id, 2061)
    assert len(journal(store).page(action='expired')['items']) == 1


def test_probe_transition_not_each_poll(tmp_path):
    store, creds = connected(tmp_path)
    log = journal(store)
    for at, available in ((2000, True), (2001, True), (2002, False), (2003, False)):
        log.transition(creds.client_id, 'ha_available', available, at)
    rows = log.page(action='ha_available')['items']
    assert len(rows) == 2 and [r['at'] for r in rows] == [2002, 2000]


def test_startup_marks_previous_unclean_session(tmp_path):
    store, _ = connected(tmp_path)
    journal(store).startup(2000)
    journal(Store(store.path, 'example.org')).startup(2001)
    assert len(journal(store).page(action='unclean_shutdown')['items']) == 1
    journal(store).shutdown(2002)
    journal(store).startup(2003)
    assert len(journal(store).page(action='unclean_shutdown')['items']) == 1


def test_backup_v3_journal_v1_v2_compatible(tmp_path):
    from server.app.backup import export_state, restore_state
    from server.app.identity import Authority
    from server.app.pki import ensure_pki
    store, creds = connected(tmp_path/'source')
    Authority(store.path.parent/'identity.key', 'http://127.0.0.1:19000')
    ensure_pki(store.path.parent/'pki', 'tunnel.example.org')
    before = journal(store).page()['items']
    blob = export_state(store.path.parent, store, 'a strong test password')
    assert blob[:5] == b'HATB3'
    target = tmp_path/'target'
    restore_state(blob, 'a strong test password', target, 'example.org', 'tunnel.example.org')
    restored = Store(target/'state.db', 'example.org')
    assert journal(restored).page()['items'] == before
    restored.revoke(creds.client_id)
    assert journal(restored).page()['items'][0]['id'] > before[0]['id']


async def test_journal_export_rejects_bad_filters_before_streaming(tmp_path):
    from aiohttp.test_utils import TestClient, TestServer
    from server.app.identity import Authority
    from server.app.web import make_ingress_app
    store, _ = connected(tmp_path)
    async def disconnect(cid): store.revoke(cid)
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    app=make_ingress_app(store,Authority(tmp_path/'identity.key','http://localhost'),options,disconnect)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get('/api/journal')).status == 403
        headers={'X-Remote-User-Id':'owner'}
        response=await client.get('/api/journal/export?since=nan',headers=headers)
        assert response.status == 400


async def test_journal_calendar_filter_uses_ha_timezone(tmp_path):
    from aiohttp.test_utils import TestClient,TestServer
    from server.app.identity import Authority
    from server.app.web import make_ingress_app
    from datetime import datetime,timezone
    from types import SimpleNamespace
    store,_=connected(tmp_path)
    for hour in (20,22):
        journal(store).record('test_day',datetime(2026,1,1,hour,tzinfo=timezone.utc).timestamp())
    async def disconnect(cid): pass
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    setup=SimpleNamespace(detected={'timezone':'Europe/Moscow'})
    app=make_ingress_app(store,Authority(tmp_path/'identity.key','http://localhost'),options,disconnect,setup=setup)
    async with TestClient(TestServer(app)) as client:
        response=await client.get('/api/journal?action=test_day&since_day=2026-01-02&until_day=2026-01-02',headers={'X-Remote-User-Id':'owner'})
        rows=(await response.json())['items']
        assert len(rows)==1 and rows[0]['at']==datetime(2026,1,1,22,tzinfo=timezone.utc).timestamp()


async def test_web_revoke_actor_is_preserved_with_legacy_disconnect(tmp_path):
    from aiohttp.test_utils import TestClient, TestServer
    from server.app.identity import Authority
    from server.app.web import make_ingress_app
    store, creds = connected(tmp_path)
    async def disconnect(cid): store.revoke(cid)
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    async with TestClient(TestServer(make_ingress_app(store,Authority(tmp_path/'identity.key','http://localhost'),options,disconnect))) as client:
        headers={'X-Remote-User-Id':'owner'}
        state=await(await client.get('/api/state',headers=headers)).json()
        headers['X-CSRF-Token']=state['csrf']
        assert (await client.post('/api/clients/'+creds.client_id+'/revoke',headers=headers,json={})).status == 200
        row=journal(store).page(action='revoke')['items'][0]
        assert row['source']=='web' and row['user_id']=='owner'


def test_original_v2_backup_remains_readable(tmp_path):
    import base64
    import json
    import secrets
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from server.app.backup import export_state, restore_state, key
    from server.app.identity import Authority
    from server.app.pki import ensure_pki
    store, creds=connected(tmp_path/'source')
    Authority(store.path.parent/'identity.key','http://localhost')
    ensure_pki(store.path.parent/'pki','tunnel.example.org')
    password='a strong test password'
    latest=export_state(store.path.parent,store,password)
    payload=json.loads(AESGCM(key(password,latest[5:21])).decrypt(latest[21:33],latest[33:],latest[:5]))
    payload.pop('audit'); payload['version']=2
    salt,nonce=secrets.token_bytes(16),secrets.token_bytes(12)
    blob=b'HATB2'+salt+nonce+AESGCM(key(password,salt)).encrypt(nonce,json.dumps(payload).encode(),b'HATB2')
    restore_state(blob,password,tmp_path/'target','example.org','tunnel.example.org')
    assert Store(tmp_path/'target/state.db','example.org',clock=lambda:2000).authenticate(creds.client_id,creds.secret) is None


def test_external_operation_survives_interruption_and_state_replacement(tmp_path):
    from server.app.journal import Journal,Actor
    store,_=connected(tmp_path/'old')
    pending=tmp_path/'external-operations.json'
    history=Journal(store,operations_path=pending)
    operation=history.request('backup_restore',2000,actor=Actor('web','owner'))
    replacement=Store(tmp_path/'new/state.db','example.org',clock=lambda:3000)
    recovered=Journal(replacement,operations_path=pending); recovered.startup(3000)
    rows=recovered.page(action='backup_restore')['items']
    assert [row['result'] for row in rows]==['unknown','requested']
    assert all(row['operation_id'].startswith(operation+':') for row in rows)
    recovered.startup(3001)
    assert len(recovered.page(action='backup_restore')['items'])==2


def test_external_operation_result_is_correlated_and_idempotent(tmp_path):
    from server.app.journal import Journal
    store,_=connected(tmp_path)
    history=Journal(store)
    operation=history.request('settings',2000)
    history.finish(operation,'success',2001); history.finish(operation,'success',2002)
    rows=history.page(action='settings')['items']
    assert len(rows)==2 and rows[0]['result']=='success'
    assert all(row['operation_id'].startswith(operation+':') for row in rows)


def test_journal_catalog_retains_deleted_identity_on_reused_domain(tmp_path):
    store,creds=connected(tmp_path)
    store.revoke(creds.client_id); snap=store.access_snapshot(creds.client_id,store.now())
    store.delete_revoked(creds.client_id,snap['revision'])
    new=store.issue('alpha',2000)
    catalog=journal(store).catalog()
    identities={row['client_id']:row for row in catalog['clients']}
    assert identities[creds.client_id]['deleted'] and not identities[new.client_id]['deleted']
    assert identities[creds.client_id]['domain']==identities[new.client_id]['domain']
    assert catalog['events']>=5 and catalog['estimated_bytes']>0


@pytest.mark.parametrize('bound',['events','bytes'])
async def test_backup_limit_has_actionable_http_error_and_no_truncation(tmp_path,monkeypatch,bound):
    from aiohttp.test_utils import TestClient,TestServer
    from server.app.identity import Authority
    from server.app.pki import ensure_pki
    from server.app.web import make_ingress_app
    from server.app import backup
    store,_=connected(tmp_path); authority=Authority(tmp_path/'identity.key','http://localhost')
    ensure_pki(tmp_path/'pki','tunnel.example.org')
    before=journal(store).page()['items']
    monkeypatch.setattr(backup,'EXPORT_EVENT_LIMIT' if bound=='events' else 'EXPORT_RAW_LIMIT',1)
    async def disconnect(cid): pass
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['owner'],'server_url':'https://tunnel.example.org'}
    app=make_ingress_app(store,authority,options,disconnect,backup_export=lambda password:backup.export_state(tmp_path,store,password))
    async with TestClient(TestServer(app)) as client:
        headers={'X-Remote-User-Id':'owner'}
        state=await(await client.get('/api/state',headers=headers)).json(); headers['X-CSRF-Token']=state['csrf']
        response=await client.post('/api/backup/export',headers=headers,json={'password':'a strong backup password'})
        result=await response.json()
        assert response.status==413 and result['error']=='backup_too_large'
        assert 'CSV' in result['message'] and 'состояни' in result['message']
    assert journal(store).page()['items']==before
