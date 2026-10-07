from pathlib import Path
import time
try:
    healthy=time.time()-int(Path('/tmp/ha-tunnel-health').read_text())<120
except Exception:
    healthy=False
raise SystemExit(0 if healthy else 1)
