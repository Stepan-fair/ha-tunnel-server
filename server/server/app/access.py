"""Persist access decisions before closing the selected client's streams."""
import asyncio
import sqlite3


class AccessService:
    def __init__(self, store, relay, clock):
        self.store, self.relay, self.clock = store, relay, clock

    def now(self): return self.clock.now() if hasattr(self.clock, 'now') else self.clock()

    async def command(self, client_id, action, command_id, expected_revision, duration=None, timezone='UTC', *, actor=None):
        async with self.relay.locks[client_id]:
            result = self.store.apply_access(client_id, action, command_id, expected_revision, self.now(), duration, timezone, actor=actor)
        if self.store.access_snapshot(client_id, self.now())['access_state'] != 'allowed':
            await self.relay.disconnect(client_id)
        return result

    async def redeem(self, code, expected_client_id=None):
        # Redemption cannot await between the transactional generation change and closing old sessions.
        result = self.store.redeem(code, int(self.now()), expected_client_id=expected_client_id)
        await self.relay.disconnect(result.client_id)
        return result

    async def expire_once(self):
        for client in self.store.list_clients():
            try: self.store.record_expiry(client['client_id'],self.now())
            except sqlite3.Error: pass  # Storage failure must never keep an expired stream open.
            if client['access_state'] != 'allowed': await self.relay.disconnect(client['client_id'])

    async def quiesce(self): await self.relay.close()

    async def delete_revoked(self, client_id, expected_revision, *, actor=None):
        async with self.relay.locks[client_id]:
            result=self.store.delete_revoked(client_id,expected_revision,actor=actor)
        await self.relay.disconnect(client_id)
        return result
