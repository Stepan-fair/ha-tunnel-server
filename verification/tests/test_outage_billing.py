import asyncio
import os
import subprocess
import sys
import pytest
from server.app.availability import AvailabilityService
from tests.test_availability import Clock, healthy
from tests.test_billing_store import funded, operations, ZONE

async def test_process_death_after_recovery_commit_cannot_double_compensate(tmp_path):
    store,creds,repo,now,snap=funded(tmp_path)
    clock=Clock(now[0]); store.clock=clock
    await AvailabilityService(store,clock,probe=healthy).recover()
    resumed=now[0]+37*3600
    script="""import asyncio,os,sys
from server.app.store import Store
from server.app.availability import AvailabilityService
class Clock:
    reliable=True
    def now(self): return float(sys.argv[2])
async def probe(): return dict(frp=True,gateway=True,npm=True)
s=Store(sys.argv[1],'example.org',clock=Clock())
asyncio.run(AvailabilityService(s,s.clock,probe=probe).recover())
os._exit(23)
"""
    result=await asyncio.to_thread(subprocess.run,[sys.executable,'-c',script,str(store.path),str(resumed)],timeout=20,capture_output=True)
    assert result.returncode==23,result.stderr
    clock.value=resumed+1
    await AvailabilityService(store,clock,probe=healthy).recover()
    assert len(operations(store,'compensation'))==1
    assert store.access_snapshot(creds.client_id,clock.value)['billing']['paid_until']==snap['billing']['paid_until']+2*86400
