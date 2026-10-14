import runpy
import time
from pathlib import Path
import pytest

@pytest.mark.parametrize('stamp,want',[(100.0,0),(1.0,0),(-20.0,1),(101.0,1),('broken',1),('nan',1),('inf',1)])
def test_healthcheck_bounded_monotonic_age(tmp_path,monkeypatch,stamp,want):
    health=tmp_path/'health'; health.write_text(str(stamp))
    original=Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**kw:original(health,*a,**kw) if str(self).replace('\\','/')=='/tmp/ha-tunnel-health' else original(self,*a,**kw))
    monkeypatch.setattr(time,'monotonic',lambda:100.0)
    for wall in (-100000,100000000):
        monkeypatch.setattr(time,'time',lambda:wall)
        with pytest.raises(SystemExit) as result: runpy.run_path('tools/healthcheck.py')
        assert result.value.code==want

async def test_shared_writer_checker_and_packaged_paths_ignore_calendar(tmp_path,monkeypatch):
    from shared.liveness import write_heartbeat
    from tools.package import package
    health=tmp_path/'health'
    monkeypatch.setattr(time,'monotonic',lambda:1000.25)
    write_heartbeat(health)
    assert float(health.read_text())==1000.25
    # A healthy timer may only report the oldest supervised loop's progress.
    write_heartbeat(health,[1000.0,800.0])
    assert float(health.read_text())==800.0
    output=tmp_path/'repo'; package(output)
    original=Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**kw:original(health,*a,**kw) if str(self).replace('\\','/')=='/tmp/ha-tunnel-health' else original(self,*a,**kw))
    for role in ('server','client'):
        for wall in (-999999,9999999999):
            monkeypatch.setattr(time,'time',lambda:wall)
            with pytest.raises(SystemExit) as result: runpy.run_path(str(output/role/'tools/healthcheck.py'))
            assert result.value.code==1
        write_heartbeat(health)
        with pytest.raises(SystemExit) as result: runpy.run_path(str(output/role/'tools/healthcheck.py'))
        assert result.value.code==0
        write_heartbeat(health,[800.0])

async def test_client_writer_follows_monitor_completion_not_independent_timer(tmp_path,monkeypatch):
    import asyncio
    from client.app.main import watch_client
    class Controller:
        async def monitor_once(self): await asyncio.Event().wait()
    health=tmp_path/'health'
    pending=asyncio.create_task(watch_client(Controller(),health))
    await asyncio.sleep(.02)
    assert not health.exists()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError): await pending
    class Completed:
        async def monitor_once(self): pass
    pending=asyncio.create_task(watch_client(Completed(),health))
    await asyncio.sleep(.02)
    assert 0<=time.monotonic()-float(health.read_text())<1
    pending.cancel()
    with pytest.raises(asyncio.CancelledError): await pending
