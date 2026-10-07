"""Server access time never rolls backwards or silently extends timed access."""
import math
import time


class SafeClock:
    def __init__(self, wall=time.time, monotonic=time.monotonic, anchor=0):
        self.wall, self.monotonic = wall, monotonic
        observed = float(wall())
        if not math.isfinite(observed) or not math.isfinite(anchor) or anchor < 0:
            raise ValueError('Invalid clock anchor')
        self._value = max(observed, anchor)
        self._mono = monotonic()
        self._reliable = observed + 1 >= self._value

    def now(self):
        mono, observed = self.monotonic(), float(self.wall())
        valid = math.isfinite(observed)
        if not valid:
            self._reliable = False
            observed = self._value
        elapsed = max(0, mono - self._mono)
        self._value = max(self._value + elapsed, observed)
        self._mono = mono
        self._reliable = valid and observed + 1 >= self._value
        return self._value

    @property
    def reliable(self):
        self.now()
        return self._reliable

    def checkpoint(self):
        return self.now()
