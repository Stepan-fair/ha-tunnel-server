"""Transient watchdog checkpoints independent of financial/calendar time."""
import time
from shared.files import atomic_write


def write_heartbeat(path,checkpoints=None):
    now=time.monotonic()
    stamp=min([now,*checkpoints]) if checkpoints is not None else now
    atomic_write(path,str(stamp).encode())
