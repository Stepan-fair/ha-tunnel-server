"""A valid replacement code alone must not evict an existing installation."""
import time

import pytest
from aiohttp import encode_basic_auth
from aiohttp.test_utils import TestClient, TestServer

from server.app.identity import Authority
from server.app.store import Store
from server.app.web import make_public_app, make_ingress_app


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org')
    authority = Authority(tmp_path/'identity.key', 'http://127.0.0.1:19000')
    options = {'server_url': 'https://tunnel.example.org',
               'tunnel_host': 'tunnel.example.org', 'tunnel_port': 7000,
               'ca_pem': 'PUBLIC CA', 'trusted_proxy_ips': ['127.0.0.1']}
    now = int(time.time())
    original = store.redeem(store.issue('alpha', now).code, now)
    invitation = store.reissue(original.client_id, now)
    return store, authority, options, now, original, invitation


@pytest.mark.parametrize('revoked', [False, True])
@pytest.mark.parametrize('knows_client_id', [False, True])
async def test_other_installation_cannot_redeem_ordinary_replacement(setup, revoked, knows_client_id):
    store, authority, options, now, original, invitation = setup
    if revoked:
        store.revoke(original.client_id)
        invitation = store.reissue(original.client_id, now)
    before = store.list_clients()
    payload = {'code': invitation.code}
    if knows_client_id:
        payload['expected_client_id'] = original.client_id
    async with TestClient(TestServer(make_public_app(store, authority, options))) as client:
        response = await client.post('/v1/enroll', json=payload,
                                     headers={'X-Forwarded-Proto': 'https'})
        assert response.status == 409
        assert (await response.json())['error'] == 'domain_bound'
        assert store.list_clients() == before
        assert store.show_code(original.client_id, now).code == invitation.code
        assert store.status_authenticate(original.client_id, original.secret)


async def test_wrong_installation_credentials_do_not_consume_replacement(setup):
    store, authority, options, now, original, invitation = setup
    other = store.redeem(store.issue('bravo', now).code, now)
    async with TestClient(TestServer(make_public_app(store, authority, options))) as client:
        response = await client.post('/v1/enroll', json={'code': invitation.code}, headers={
            'X-Forwarded-Proto': 'https',
            'Authorization': encode_basic_auth(other.client_id, other.secret)})
        assert response.status == 409
        assert store.authenticate(original.client_id, original.secret)
        response = await client.post('/v1/enroll', json={'code': invitation.code}, headers={
            'X-Forwarded-Proto': 'https',
            'Authorization': encode_basic_auth(original.client_id, original.secret)})
        assert response.status == 200
        replacement = await response.json()
        assert replacement['client_id'] == original.client_id
        assert store.authenticate(original.client_id, original.secret) is None
        assert store.authenticate(original.client_id, replacement['secret'])


async def transfer_code(setup, *, revision=None, domain=None):
    store, authority, options, now, original, invitation = setup
    options = {**options, 'admin_user_ids': ['owner'], 'ingress_ips': ['127.0.0.1']}
    async def disconnect(client_id):
        pytest.fail('Issuing a transfer code must keep the current connection')
    async with TestClient(TestServer(make_ingress_app(store, authority, options, disconnect))) as client:
        headers = {'X-Remote-User-Id': 'owner'}
        state = await (await client.get('/api/state', headers=headers)).json()
        headers['X-CSRF-Token'] = state['csrf']
        current = store.access_snapshot(original.client_id, now)
        response = await client.post('/api/clients/'+original.client_id+'/invitation/transfer',
            headers=headers, json={'revision': current['revision'] if revision is None else revision,
                                   'command_id':'transfer-test','confirm_domain': original.domain if domain is None else domain})
        return response.status, await response.json()


async def test_confirmed_transfer_is_persistent_one_use_and_keeps_business_state(setup):
    from shared.protocol import Invitation
    store, authority, options, now, original, invitation = setup
    store.add_traffic(original.client_id, 17, 29)
    before = store.access_snapshot(original.client_id, now)
    status, result = await transfer_code(setup)
    assert status == 200
    assert result['purpose'] == 'transfer'
    assert store.authenticate(original.client_id, original.secret)
    code = Invitation.parse(result['invitation']).code
    reopened = Store(store.path, 'example.org')
    async with TestClient(TestServer(make_public_app(reopened, authority, options))) as client:
        response = await client.post('/v1/enroll', json={'code': code},
                                     headers={'X-Forwarded-Proto': 'https'})
        assert response.status == 200
        new = await response.json()
        assert new['client_id'] == original.client_id and new['domain'] == original.domain
        assert reopened.authenticate(original.client_id, original.secret) is None
        assert reopened.authenticate(original.client_id, new['secret'])
        after = reopened.access_snapshot(original.client_id, now)
        for key in ('paused', 'deadline', 'duration', 'billing_mode', 'price_kopecks',
                    'balance_kopecks', 'paid_from', 'paid_until', 'to_client_bytes', 'from_client_bytes'):
            assert after.get(key) == before.get(key)
        assert (await client.post('/v1/enroll', json={'code': code},
                                  headers={'X-Forwarded-Proto': 'https'})).status == 400


@pytest.mark.parametrize('revision,domain,status', [(999, None, 409), (None, 'bravo.example.org', 400)])
async def test_transfer_requires_current_revision_and_exact_domain(setup, revision, domain, status):
    store, authority, options, now, original, invitation = setup
    before = store.list_clients()
    actual, body = await transfer_code(setup, revision=revision, domain=domain)
    assert actual == status
    assert store.list_clients() == before
    assert store.authenticate(original.client_id, original.secret)


async def test_ordinary_reissue_cancels_transfer_authorization(setup):
    store, authority, options, now, original, invitation = setup
    status, result = await transfer_code(setup)
    assert status == 200
    ordinary = store.reissue(original.client_id, now, replace_pending=True)
    async with TestClient(TestServer(make_public_app(store, authority, options))) as client:
        response = await client.post('/v1/enroll', json={'code': ordinary.code},
                                     headers={'X-Forwarded-Proto': 'https'})
        assert response.status == 409
        assert store.authenticate(original.client_id, original.secret)


async def test_client_maps_only_known_enrollment_errors_to_local_safe_message():
    from aiohttp import ClientSession, web
    from client.app.enrollment import post_json
    async def occupied(request):
        return web.json_response({'error': 'domain_bound', 'message': 'secret SHOULD_NOT_APPEAR'}, status=409)
    app = web.Application()
    app.router.add_post('/', occupied)
    async with TestServer(app) as server, ClientSession() as session:
        with pytest.raises(ValueError, match='Домен уже привязан к другому Home Assistant') as caught:
            await post_json(session, str(server.make_url('/')), json={})
        assert 'SHOULD_NOT_APPEAR' not in str(caught.value)


async def test_wrong_code_error_keeps_existing_client_connected(tmp_path, monkeypatch):
    from aiohttp import ClientSession, web
    from client.app.enrollment import post_json, load_credentials
    import client.app.controller as module
    from tests.test_client_recovery import controller
    ctrl, original = controller(tmp_path)
    ctrl.state = 'connected'
    ctrl.runtime.status = lambda: {'running': True}
    async def ready(*args): pass
    monkeypatch.setattr(module, 'check_http_ready', ready)
    async def occupied(request):
        return web.json_response({'error': 'domain_bound'}, status=409)
    app = web.Application()
    app.router.add_post('/', occupied)
    async with TestServer(app) as server, ClientSession() as session:
        async def enroll(*args, **kwargs):
            return await post_json(session, str(server.make_url('/')), json={})
        monkeypatch.setattr(module, 'enroll', enroll)
        await ctrl.rebind('test-code')
    assert ctrl.state == 'connected'
    assert ctrl.runtime.stopped == 0
    assert load_credentials(ctrl.directory) == original
    assert 'Домен уже привязан' in ctrl.status()['operation_error']


async def test_code_for_other_connection_has_specific_error_without_consumption(setup):
    store, authority, options, now, original, invitation = setup
    async with TestClient(TestServer(make_public_app(store, authority, options))) as client:
        response = await client.post('/v1/enroll', json={'code': invitation.code, 'expected_client_id': 'b'*32},
                                     headers={'X-Forwarded-Proto': 'https'})
        assert response.status == 409
        assert (await response.json())['error'] == 'wrong_connection'
        assert store.show_code(original.client_id, now).code == invitation.code


async def test_expired_transfer_never_revokes_current_installation(setup):
    from shared.protocol import Invitation
    store, authority, options, now, original, invitation = setup
    status, result = await transfer_code(setup)
    assert status == 200
    code = Invitation.parse(result['invitation']).code
    with pytest.raises(ValueError):
        store.redeem(code, result['expires'])
    assert store.authenticate(original.client_id, original.secret)


def test_two_replacement_requests_have_exactly_one_winner(setup):
    from concurrent.futures import ThreadPoolExecutor
    store, authority, options, now, original, invitation = setup
    def redeem(_):
        try:
            return store.redeem(invitation.code, now, binding=(original.client_id, original.secret))
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        winners = [result for result in pool.map(redeem, range(4)) if result is not None]
    assert len(winners) == 1
    assert store.authenticate(original.client_id, original.secret) is None
    assert store.authenticate(original.client_id, winners[0].secret)
    assert store.access_snapshot(original.client_id, now)['generation'] == 1


def test_transfer_preserves_paid_manual_pause_and_full_monetary_history(tmp_path):
    from tests.test_billing_store import funded, operations
    store, original, repo, now, snapshot = funded(tmp_path)
    store.apply_access(original.client_id, 'pause', 'pause', snapshot['revision'], now[0])
    before = store.access_snapshot(original.client_id, now[0])
    history = operations(store)
    invitation = store.reissue(original.client_id, int(now[0]), transfer=True,
        expected_revision=before['revision'], confirm_domain=original.domain)
    new = store.redeem(invitation.code, int(now[0]))
    after = store.access_snapshot(original.client_id, now[0])
    assert after['paused'] is True
    assert after['billing'] == before['billing']
    assert operations(store) == history
    assert store.authenticate(new.client_id, new.secret) is None, 'Manual pause remains enforced'
    assert store.status_authenticate(new.client_id, new.secret)
    assert store.status_authenticate(original.client_id, original.secret) is None


def test_backup_with_pending_transfer_restores_without_transfer_authorization(tmp_path):
    from server.app.backup import export_state, restore_state
    from server.app.pki import ensure_pki
    source, target = tmp_path/'source', tmp_path/'target'
    store = Store(source/'state.db', 'example.org')
    Authority(source/'identity.key', 'http://127.0.0.1:19000')
    ensure_pki(source/'pki', 'tunnel.example.org')
    now = int(time.time())
    original = store.redeem(store.issue('alpha', now).code, now)
    invitation = store.reissue(original.client_id, now, transfer=True,
        expected_revision=0, confirm_domain=original.domain)
    blob = export_state(source, store, 'a strong test password')
    restore_state(blob, 'a strong test password', target, 'example.org', 'tunnel.example.org')
    restored = Store(target/'state.db', 'example.org')
    with pytest.raises(ValueError): restored.redeem(invitation.code, now)
    ordinary = restored.reissue(original.client_id, now)
    with pytest.raises(ValueError): restored.redeem(ordinary.code, now)
    with restored.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM server_metadata WHERE name GLOB 'invitation_transfer:*'").fetchone()[0] == 0


async def test_preparation_failure_during_rebind_keeps_running_client_monitorable(tmp_path, monkeypatch):
    from client.app.ha_config import ConfigProblem
    import client.app.controller as module
    from tests.test_client_recovery import controller
    ctrl, original = controller(tmp_path)
    ctrl.state = 'connected'
    ctrl.runtime.status = lambda: {'running': True}
    async def not_ready(*args): raise ConfigProblem('HTTP confirmation is temporarily unavailable')
    monkeypatch.setattr(module, 'check_http_ready', not_ready)
    await ctrl.rebind('test-code')
    assert ctrl.state == 'connected'
    assert ctrl.runtime.stopped == 0
    assert ctrl.credentials == original
    assert 'temporarily unavailable' in ctrl.status()['operation_error']
