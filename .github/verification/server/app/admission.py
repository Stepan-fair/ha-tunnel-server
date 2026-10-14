"""Bounded, single-owner FRP admission. All deadlines use monotonic time.

The credential authenticates a client; the process nonce is only a reconnect
hint, not a second secret. A full clone of runtime state is indistinguishable.
The event-loop policy handler calls these synchronous methods without awaits.
"""
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import time


@dataclass
class _Owner:
    generation: int
    run_id: str
    nonce: str | None
    epoch: str
    expires: float
    active: bool = False
    proxy_candidate: bool = False
    proof_epoch: str | None = None


class Admission:
    RESERVATION_SECONDS = 15
    LEASE_SECONDS = 120

    def __init__(self, clock=time.monotonic, *, max_owners=4096, max_reservations=256):
        if any(type(v) is not int or v < 1 for v in (max_owners, max_reservations)):
            raise ValueError('Admission budgets must be positive integers')
        self.clock = clock
        self.max_owners = max_owners
        self.max_reservations = min(max_reservations, max_owners)
        self._owners = {}
        self._run_key = secrets.token_bytes(32)

    def _prune(self):
        now = self.clock()
        for client_id in [key for key, owner in self._owners.items() if owner.expires <= now]:
            del self._owners[client_id]

    def login(self, client_id, generation, run_id, process_nonce):
        # Bound values retained in memory, including attacker-controlled hints.
        if (not isinstance(client_id, str) or not 1 <= len(client_id) <= 64 or
                type(generation) is not int or generation < 0 or
                not isinstance(run_id, str) or len(run_id) > 128 or
                (process_nonce is not None and
                 (not isinstance(process_nonce, str) or not 1 <= len(process_nonce) <= 128))):
            return None
        self._prune()
        old = self._owners.get(client_id)
        if old is not None:
            if generation != old.generation:
                return None  # Authority changes must explicitly remove the old owner.
            same = (process_nonce == old.nonce if old.nonce is not None
                    else process_nonce is None and run_id == old.run_id)
            if not same:
                return None
        reservations = sum(not owner.active for owner in self._owners.values())
        if (old is None and len(self._owners) >= self.max_owners or
                (old is None or old.active) and reservations >= self.max_reservations):
            return None
        # Stable for this client across expiry/rebind: FRP replaces its predecessor
        # instead of accumulating controls. A random boot key avoids any historic
        # client->RunID cache; 128-bit hex satisfies pinned FRP ValidateRunID.
        canonical = hmac.new(self._run_key, client_id.encode(), hashlib.sha256).hexdigest()[:32]
        deadline = self.clock() + self.RESERVATION_SECONDS
        if old is not None and not old.active:
            deadline = min(deadline, old.expires)  # Login alone never extends a reservation.
        owner = _Owner(generation, canonical, process_nonce, secrets.token_hex(16), deadline)
        self._owners[client_id] = owner
        return {'client_id':client_id, 'generation':generation, 'run_id':canonical, 'epoch':owner.epoch}

    def _matching(self, client_id, generation, run_id, epoch):
        owner = self._owners.get(client_id)
        if (owner is None or owner.expires <= self.clock() or
                (owner.generation, owner.run_id, owner.epoch) != (generation, run_id, epoch)):
            return None
        return owner

    def activity(self, client_id, generation, run_id, epoch, operation):
        if operation not in ('NewProxy', 'NewWorkConn', 'Ping'):
            return False
        owner = self._matching(client_id, generation, run_id, epoch)
        if owner is None:
            return False
        owner.active = True
        owner.expires = self.clock() + self.LEASE_SECONDS
        if operation == 'NewProxy':
            owner.proxy_candidate = True  # Authorization, never publication proof.
        return True

    def close_proxy(self, client_id, generation, run_id, epoch):
        owner = self._matching(client_id, generation, run_id, epoch)
        if owner is None:
            return False
        owner.proxy_candidate = False
        owner.proof_epoch = secrets.token_hex(16)
        return True  # CloseProxy neither logs out nor renews the owner.

    def epoch(self, client_id, generation):
        owner = self._owners.get(client_id)
        if owner and owner.generation == generation and owner.active and owner.expires > self.clock():
            return owner.epoch
        return None

    def proof(self, client_id, generation):
        epoch = self.epoch(client_id, generation)
        if epoch is not None:
            return (epoch, self._owners[client_id].proof_epoch)
        return None

    def connected(self, client_id, generation):
        return self.epoch(client_id, generation) is not None

    def remove(self, client_id):
        self._owners.pop(client_id, None)

    def clear(self):
        self._owners.clear()

    def counts(self):
        self._prune()
        active = sum(owner.active for owner in self._owners.values())
        return {'owners':len(self._owners), 'reservations':len(self._owners)-active, 'active':active}
