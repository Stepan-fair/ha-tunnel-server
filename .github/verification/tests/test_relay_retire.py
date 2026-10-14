import asyncio

import pytest

from server.app.access import AccessService
from server.app.relay import ClientRelay
from server.app.store import Store


def setup(tmp_path):
    store = Store(tmp_path/'state.db', 'example.org', clock=lambda: 2000)
    a, b = [store.redeem(store.issue(n,1000).code,1001) for n in ('alpha','bravo')]
    relay = ClientRelay(store, store.clock)
    return store, a, b, relay


async def test_deleted_pending_does_not_poison_surviving_traffic(tmp_path):
    store, a, b, relay = setup(tmp_path)
    relay.pending[a.client_id] = [17,23]
    relay.pending[b.client_id] = [31,47]
    store.revoke(a.client_id)
    await AccessService(store,relay,store.clock).delete_revoked(a.client_id,1)
    await relay.flush()
    snap = store.access_snapshot(b.client_id,2000)
    assert (snap['to_client_bytes'],snap['from_client_bytes']) == (31,47)
    assert a.client_id not in relay.pending
    assert relay.telemetry_error is None


async def test_retire_timeout_guards_late_accrual_and_keeps_waited_lock(tmp_path):
    store, a, b, relay = setup(tmp_path)
    cid = a.client_id
    entered, release = asyncio.Event(), asyncio.Event()
    lock = relay.locks[cid]
    await lock.acquire()
    async def resistant():
        entered.set()
        try: await asyncio.Future()
        except asyncio.CancelledError: await release.wait()
    task = asyncio.create_task(resistant())
    relay.client_tasks[cid].add(task)
    await entered.wait()
    waiter = asyncio.create_task(lock.acquire())
    await asyncio.sleep(0)
    store.revoke(cid); store.delete_revoked(cid,1)
    try:
        assert await relay.retire(cid, .01) is False
        assert relay.locks[cid] is lock
        class Writer:
            def write(self,data): pass
            async def drain(self): pass
        with pytest.raises(ConnectionError): await relay._write(Writer(),b'late',cid,0)
        assert cid not in relay.pending
        release.set(); await task
        relay.client_tasks[cid].discard(task)
        lock.release(); await waiter
        assert await relay.retire(cid,.01) is False
        lock.release()
        assert await relay.retire(cid,.1) is True
        assert cid not in relay.locks
    finally:
        release.set(); task.cancel(); waiter.cancel()
        await asyncio.gather(task,waiter,return_exceptions=True)


async def test_live_sqlite_failure_and_overflow_retain_counts_but_flush_survivor(tmp_path):
    store,a,b,relay = setup(tmp_path)
    with store.connection() as db:
        db.execute("CREATE TRIGGER fail_traffic BEFORE UPDATE OF to_client_bytes ON clients WHEN OLD.id='"+a.client_id+"' BEGIN SELECT RAISE(FAIL,'transient'); END")
    relay.pending[a.client_id]=[17,23]; relay.pending[b.client_id]=[31,47]
    await relay.flush()
    assert relay.pending[a.client_id]==[17,23]
    assert store.access_snapshot(b.client_id,2000)['from_client_bytes']==47
    assert relay.telemetry_error=='traffic_storage_error'
    with store.connection() as db:
        db.execute('DROP TRIGGER fail_traffic')
        db.execute('UPDATE clients SET to_client_bytes=? WHERE id=?',(2**63-1,a.client_id))
    relay.pending[b.client_id]=[31,47]
    await relay.flush()
    assert relay.pending[a.client_id]==[17,23]
    assert store.access_snapshot(b.client_id,2000)['from_client_bytes']==94
    with store.connection() as db: db.execute('UPDATE clients SET to_client_bytes=0 WHERE id=?',(a.client_id,))
    await relay.flush()
    assert relay.pending[a.client_id]==[0,0]
    assert store.access_snapshot(a.client_id,2000)['from_client_bytes']==23
    assert relay.telemetry_error is None

async def test_retire_during_drain_prevents_late_counter_recreation(tmp_path):
    store,a,b,relay=setup(tmp_path)
    entered,release=asyncio.Event(),asyncio.Event()
    class Writer:
        def write(self,data): pass
        async def drain(self):
            entered.set()
            try: await release.wait()
            except asyncio.CancelledError: await release.wait()
    task=asyncio.create_task(relay._write(Writer(),b'late-count',a.client_id,0))
    relay.client_tasks[a.client_id].add(task)
    await entered.wait()
    store.revoke(a.client_id); store.delete_revoked(a.client_id,1)
    try:
        assert await relay.retire(a.client_id,.01) is False
        release.set()
        with pytest.raises(ConnectionError): await task
        assert a.client_id not in relay.pending
        relay.client_tasks[a.client_id].discard(task)
        assert await relay.retire(a.client_id,.1) is True
    finally:
        release.set(); task.cancel(); await asyncio.gather(task,return_exceptions=True)

async def test_periodic_flush_does_not_cancel_retirement_cleanup_again(tmp_path):
    store,a,b,relay=setup(tmp_path)
    entered,cleanup,release=asyncio.Event(),asyncio.Event(),asyncio.Event()
    async def stream():
        entered.set()
        try: await asyncio.Future()
        except asyncio.CancelledError:
            cleanup.set(); await release.wait()
    task=asyncio.create_task(stream()); relay.client_tasks[a.client_id].add(task)
    await entered.wait()
    store.revoke(a.client_id); store.delete_revoked(a.client_id,1)
    relay.pending[a.client_id]=[17,23]
    try:
        assert await relay.retire(a.client_id,.01) is False
        await cleanup.wait()
        await relay.flush(); await asyncio.sleep(0)
        assert not task.done(), 'A flush must not interrupt cancellation-resistant cleanup'
        assert a.client_id in relay.retiring
        release.set(); await task
        await relay.flush()
        assert a.client_id not in relay.retiring and a.client_id not in relay.pending
    finally:
        release.set(); task.cancel(); await asyncio.gather(task,return_exceptions=True)
