from pathlib import Path
import time
try:
    age=time.monotonic()-float(Path('/tmp/ha-tunnel-health').read_text())
    healthy=0<=age<120
except Exception:
    healthy=False
raise SystemExit(0 if healthy else 1)
