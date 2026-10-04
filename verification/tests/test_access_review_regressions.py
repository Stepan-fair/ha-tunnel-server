import asyncio
import sqlite3
from datetime import datetime, timezone
import pytest
from server.app.duration import Duration, deadline_at
from server.app.store import Store
from server.app.identity import Authority
from server.app.policy import authorize
from server.app.relay import ClientRelay
from server.app.telemetry import TelemetryService


def populated(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org', clock=lambda: 2000)
    a, b = [store.redeem(store.issue(n, 1000).code, 1001) for n in ('alpha', 'bravo')]
    return store, a, b


def test_elapsed_hours_preserve_second_dst_occurrence():
    start = datetime(2026, 10, 25, 1, 30, tzinfo=timezone.utc)
    for hours in (1, 2):
        end = deadline_at(start, Duration(hours=hours), 'Europe/Berlin')
        assert (end-start).total_seconds() == hours*3600


def test_wrong_client_code_does_not_mutate_either_record(tmp_path):
    store, a, b = populated(tmp_path)
    invitation = store.reissue(b.client_id, 2000)
    before = store.list_clients()
    with pytest.raises(ValueError):
        store.redeem(invitation.code, 2000, expected_client_id=a.client_id)
    assert store.list_clients() == before
    assert store.authenticate(a.client_id, a.secret)
    assert store.authenticate(b.client_id, b.secret)
    assert store.show_code(b.client_id, 2000).code == invitation.code


def test_late_close_cannot_remove_new_login_in_same_generation(tmp_path):
    store, a, _ = populated(tmp_path)
    authority = Authority(tmp_path/'identity.key', 'http://127.0.0.1:19000')
    login = {'user': a.client_id, 'privilege_key': authority.issue(a.client_id)}
    old = authorize('Login', login, store, authority)['content']['metas']
    new = authorize('Login', login, store, authority)['content']['metas']
    assert old['ha_tunnel_session'] != new['ha_tunnel_session']
    proxy = {'user': {'user': a.client_id, 'metas': new}, 'proxy_type': 'http',
             'proxy_name': a.client_id+'.ha', 'custom_domains': [a.domain]}
    assert not authorize('NewProxy', proxy, store, authority)['reject']
    authorize('CloseProxy', {'user': {'user': a.client_id, 'metas': old}}, store, authority)
    assert store.live_proxies[a.client_id] == 0
    authorize('CloseProxy', {'user': {'user': a.client_id, 'metas': new}}, store, authority)
    assert a.client_id not in store.live_proxies


def test_rebound_proxy_uses_server_generation_route(tmp_path):
    store, a, _ = populated(tmp_path)
    store.redeem(store.reissue(a.client_id, 2000).code, 2000)
    authority = Authority(tmp_path/'identity.key', 'http://127.0.0.1:19000')
    login = authorize('Login', {'user': a.client_id, 'privilege_key': authority.issue(a.client_id, generation=1)}, store, authority)
    proxy = {'user': {'user': a.client_id, 'metas': login['content']['metas']}, 'proxy_type': 'http',
             'proxy_name': a.client_id+'.ha', 'custom_domains': [a.domain]}
    normalized = authorize('NewProxy', proxy, store, authority)['content']
    assert normalized['custom_domains'] != [a.domain]
    assert normalized['host_header_rewrite'] == a.domain


async def test_disconnect_aborts_even_when_graceful_close_never_finishes(tmp_path):
    store, a, _ = populated(tmp_path)
    relay = ClientRelay(store, store.clock)
    class Transport:
        aborted = False
        def abort(self): self.aborted = True
    class SlowStream:
        transport = Transport()
        def close(self): pass
        async def wait_closed(self): await asyncio.Future()
    stream = SlowStream()
    relay.streams[a.client_id].add(stream)
    await asyncio.wait_for(relay.disconnect(a.client_id), .2)
    assert stream.transport.aborted


async def test_expiry_of_other_clients_is_not_blocked_by_slow_receiver(tmp_path):
    from server.app.access import AccessService
    store, a, b = populated(tmp_path)
    relay = ClientRelay(store, store.clock)
    access = AccessService(store, relay, store.clock)
    class Stream:
        def __init__(self): self.transport = self; self.aborted = False
        def abort(self): self.aborted = True
        def close(self): pass
        async def wait_closed(self): await asyncio.Future()
    alpha, bravo = Stream(), Stream()
    for client, stream in ((a, alpha), (b, bravo)):
        store.set_capabilities(client.client_id, ['access-v1'])
        await access.command(client.client_id,'set_duration','timer',0,{'minutes':1})
        relay.streams[client.client_id].add(stream)
    store.clock = access.clock = lambda: 2061
    await asyncio.wait_for(access.expire_once(), .2)
    assert alpha.aborted and bravo.aborted


async def test_traffic_read_error_recovers_without_stale_speed(tmp_path, monkeypatch):
    store, a, _ = populated(tmp_path)
    relay = ClientRelay(store, store.clock)
    relay.rate_values[a.client_id] = (123, 0)
    original = store.list_clients
    def fail(): raise sqlite3.OperationalError('temporary')
    monkeypatch.setattr(store, 'list_clients', fail)
    await relay.flush()
    assert relay.telemetry_error == 'traffic_storage_error'
    assert relay.rates(a.client_id) is None
    monkeypatch.setattr(store, 'list_clients', original)
    relay.pending[a.client_id][0] = 7
    await relay.flush()
    assert relay.telemetry_error is None
    assert store.access_snapshot(a.client_id, 2000)['to_client_bytes'] == 7


async def test_probe_loop_survives_transient_database_error(tmp_path, monkeypatch):
    store, a, _ = populated(tmp_path)
    relay = ClientRelay(store, store.clock)
    service = TelemetryService(store, relay, store.clock)
    original = store.list_clients
    attempts = []
    async def fast_sleep(seconds): await original_sleep(.001)
    original_sleep = asyncio.sleep
    def sometimes():
        attempts.append(True)
        if len(attempts) == 1: raise sqlite3.OperationalError('temporary')
        return original()
    monkeypatch.setattr(store, 'list_clients', sometimes)
    monkeypatch.setattr('server.app.telemetry.asyncio.sleep', fast_sleep)
    await service.start()
    try:
        await original_sleep(.02)
        assert not service.task.done()
        assert len(attempts) > 1
    finally: await service.close()
