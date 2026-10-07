"""Reject token reuse, races, impersonation and unsafe domain allocation."""
import importlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


@pytest.fixture
def store(tmp_path):
    assert Path('server/app/store.py').is_file(), 'Enrollment Store not implemented'
    module = importlib.import_module('server.app.store')
    return module.Store(tmp_path / 'state.db', 'example.com', reserved={'tunnel', 'www'})


def test_redeem_authenticate_revoke(store):
    invite = store.issue('house', 1000)
    creds = store.redeem(invite.code, 1001)
    assert creds.domain == 'house.example.com'
    assert store.authenticate(creds.client_id, creds.secret).domain == creds.domain
    assert store.authenticate(creds.client_id, 'bad') is None
    store.revoke(creds.client_id)
    assert store.authenticate(creds.client_id, creds.secret) is None


def test_token_single_use_and_expiration(store):
    token = store.issue('one', 1000).code
    store.redeem(token, 1001)
    with pytest.raises(ValueError):
        store.redeem(token, 1002)
    expired = store.issue('two', 1000).code
    with pytest.raises(ValueError):
        store.redeem(expired, 1900)


def test_only_one_parallel_redemption(store):
    token = store.issue('race', 1000).code
    def redeem(_):
        try:
            return store.redeem(token, 1001)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(redeem, range(8)))
    assert sum(result is not None for result in results) == 1


def test_state_survives_restart_and_never_lists_secrets(store):
    token = store.issue('house', 1000).code
    credentials = store.redeem(token, 1001)
    reopened = type(store)(store.path, 'example.com', reserved={'tunnel', 'www'})
    assert reopened.authenticate(credentials.client_id, credentials.secret)
    with pytest.raises(ValueError):
        reopened.redeem(token, 1002)
    public = json.dumps(reopened.list_clients())
    assert token not in public and credentials.secret not in public
    raw = store.path.read_bytes()
    assert token.encode() not in raw and credentials.secret.encode() not in raw


@pytest.mark.parametrize('name', ['tunnel', 'www', 'a.b', '*.x', '-bad', 'bad-', 'x'*64,
                                  'HOUSE', 'а.example', '', 'a\nheader', '../escape'])
def test_rejects_unsafe_names(store, name):
    with pytest.raises(ValueError):
        store.issue(name, 1000)


def test_unique_names_more_than_five_clients(store):
    domains = [store.redeem(store.issue(None, 1000).code, 1001).domain for _ in range(12)]
    assert len(set(domains)) == 12
    with pytest.raises(ValueError):
        store.issue(domains[0].split('.')[0], 1001)


def test_invalid_tokens_fail_and_revoked_names_not_recycled(store):
    for token in ['', 'x'*10000, None, 42]:
        with pytest.raises(ValueError):
            store.redeem(token, 1000)
    c = store.redeem(store.issue('keep', 1000).code, 1001)
    store.revoke(c.client_id)
    with pytest.raises(ValueError):
        store.issue('keep', 2000)


def test_clock_before_issuance_is_rejected(store):
    invite = store.issue('clock', 1000)
    with pytest.raises(ValueError):
        store.redeem(invite.code, 999)
