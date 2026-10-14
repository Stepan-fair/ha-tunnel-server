"""Monotonic time with fresh, trusted host synchronization proof on every boot."""
import math
import secrets
import time


class SafeClock:
    def __init__(self, wall=time.time, monotonic=time.monotonic, anchor=0):
        self.wall, self.monotonic = wall, monotonic
        observed = float(wall())
        if not math.isfinite(observed) or not math.isfinite(anchor) or anchor < 0:
            raise ValueError('Invalid clock anchor')
        self._ever_confirmed = False
        self._anchor = float(anchor)
        self._value = max(observed, anchor)
        self._mono = monotonic()
        self._wall = observed
        self._reliable = False
        self._samples = []
        self._proof = None
        self.ambiguous = False

    def quarantine(self, *, ambiguous=True):
        self._reliable = False
        self._samples = []
        self._proof = None
        self.ambiguous = self.ambiguous or ambiguous

    def now(self):
        mono, observed = self.monotonic(), float(self.wall())
        elapsed = mono - self._mono
        if not math.isfinite(observed) or elapsed < 0 or abs(observed-self._wall-elapsed)>5:
            self.quarantine()
        self._value += max(0, elapsed)
        self._mono, self._wall = mono, observed
        return self._value

    @property
    def reliable(self):
        self.now()
        return self._reliable

    def checkpoint(self):
        value = self.now()
        if self._reliable: self._anchor = value
        return self._anchor

    def observe_host(self, info):
        self.now()
        if not isinstance(info, dict) or info.get('dt_synchronized') is not True or not math.isfinite(self._wall):
            # Waiting for the first proof does not disprove a persisted healthy
            # baseline. Losing an established proof does make time ambiguous.
            self.quarantine(ambiguous=self._proof is not None or self._ever_confirmed)
            return False
        sample = (self._mono, self._wall)
        if self._samples:
            mono, wall = self._samples[-1]
            if abs((sample[1]-wall)-(sample[0]-mono))>1:
                self.quarantine()
            elif sample[0]-mono<10:
                return self._reliable
        self._samples = (self._samples+[sample])[-3:]
        if len(self._samples)==3:
            if self._proof is None:
                self._proof = {'id':secrets.token_hex(16),'at':sample[1]}
            if sample[1]>=self._anchor:
                self._value = max(self._value,sample[1]) if self._ever_confirmed else sample[1]
                self._ever_confirmed = True
                self._reliable = True
        return self._reliable

    def confirmed_snapshot(self):
        self.now()
        return dict(self._proof) if self._proof is not None else None

    def confirmed_now(self, snapshot):
        if snapshot is None or snapshot!=self.confirmed_snapshot():
            raise ValueError('Fresh synchronized host proof required')
        return self._wall

    def repair_allowed(self, anchor):
        self.now()
        return not self._reliable and self._proof is not None and self._wall<anchor

    def accept_repair(self, value):
        # Called synchronously after the durable transaction, with no await gap.
        self._anchor = self._value = value
        self._ever_confirmed = True
        self._reliable = True
        self.ambiguous = False


class ClockMonitor:
    """Only this trusted Supervisor boundary supplies synchronization observations."""
    def __init__(self, store, clock, supervisor):
        self.store, self.clock, self.supervisor = store, clock, supervisor

    async def sample(self):
        import asyncio
        if self.store.administration.busy or self.store.migrating: return False
        try: info = await asyncio.wait_for(self.supervisor.get('/host/info'),5)
        except (OSError,ValueError,TimeoutError): info = None
        if self.store.administration.busy or self.store.migrating: return False
        self.clock.observe_host(info)
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self.store.ensure_mutation_allowed()
            from server.app.clock_repair import metadata
            if self.clock.ambiguous: metadata(db,'clock_ambiguous',True)
            proof = self.clock.confirmed_snapshot()
            if proof is not None and proof!=self.store.get_metadata('clock_proof'):
                metadata(db,'clock_proof',proof)
                # The stable financial anchor changes only with the proof epoch.
                anchor=self.clock.checkpoint()
                metadata(db,'clock_financial_anchor',anchor)
                metadata(db,'clock_anchor',anchor)
        return self.clock.reliable

    async def run(self,progress=None):
        import asyncio
        while True:
            await self.sample()
            if progress is not None: progress()
            await asyncio.sleep(10)
