"""Persist access decisions before closing the selected client's streams."""
import asyncio
import sqlite3
from server.app.billing import BillingRepository
from server.app.store import ConflictError


class AccessService:
    def __init__(self, store, relay, clock, *, diagnostics=None):
        self.store, self.relay, self.clock = store, relay, clock
        self.diagnostics=diagnostics

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

    async def billing_command(self,client_id,action,command_id,expected_revision,*,value_kopecks,timezone,actor=None):
        if not getattr(self.store,'billing_available',lambda:True)():
            raise ConflictError('Wait for service recovery before changing money')
        async with self.relay.locks[client_id]:
            result=BillingRepository(self.store).command(client_id,action,command_id,expected_revision,
                value_kopecks=value_kopecks,now=self.now(),timezone=timezone,actor=actor)
        if self.store.access_snapshot(client_id,self.now())['access_state']!='allowed':
            await self.relay.disconnect(client_id)
        return result

    async def expire_once(self):
        if getattr(self.store,'billing_available',lambda:True)():
            for client in self.store.list_clients():
                async with self.relay.locks[client['client_id']]:
                    BillingRepository(self.store).reconcile(client['client_id'],self.now(),timezone=client['billing']['timezone'])
        for client in self.store.list_clients():
            try: self.store.record_expiry(client['client_id'],self.now())
            except sqlite3.Error as exc:
                if self.diagnostics: self.diagnostics.failure('storage_error',exc,component='storage',fatal=False)
                # Storage failure must never keep an expired stream open.
            if client['access_state'] != 'allowed': await self.relay.disconnect(client['client_id'])

    async def quiesce(self): await self.relay.close()

    async def delete_revoked(self, client_id, expected_revision, *, actor=None):
        async with self.relay.locks[client_id]:
            result=self.store.delete_revoked(client_id,expected_revision,actor=actor)
        await self.relay.disconnect(client_id)
        return result
