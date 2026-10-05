import asyncio
import json
import sys
import pytest
from shared.diagnostics import Diagnostics
from shared.process_output import ProcessOutput
from shared.runtime import FrpRuntime


async def test_split_secrets_flood_and_unterminated_output(tmp_path):
    log = Diagnostics(tmp_path)
    reader = asyncio.StreamReader()
    output = ProcessOutput(log, 'frp')
    task = asyncio.create_task(output.drain(reader))
    for chunk in (b'Authorization: sec', b'ret\n', b'x'*100000, b'\n', b'bind: address already in use\n'):
        reader.feed_data(chunk)
        await asyncio.sleep(0)
    reader.feed_eof()
    await asyncio.wait_for(task, 2)
    assert len(json.dumps(list(output.tail))) < 8192
    rows = log.page()['items']
    assert any(r.get('fields', {}).get('reason') == 'address_in_use' for r in rows)
    assert 'secret' not in b''.join(log.export()).decode()


async def test_failed_verification_has_exit_diagnostic(tmp_path):
    helper = tmp_path/'bad.py'
    helper.write_text("import sys\nprint('private-secret',flush=True)\nsys.exit(2)\n")
    log = Diagnostics(tmp_path/'logs')
    runtime = FrpRuntime(sys.executable, tmp_path/'frp.json', prefix=[str(helper)], diagnostics=log)
    with pytest.raises(RuntimeError, match='configuration'):
        await runtime.start({})
    rows = log.page()['items']
    assert any(r['code']=='process_exit' and r['fields']['exit_code']==2 for r in rows)
    assert 'private-secret' not in b''.join(log.export()).decode()
    assert not runtime.status()['running']


async def test_pipe_flood_does_not_block_stop_or_restart(tmp_path):
    helper = tmp_path/'flood.py'
    helper.write_text("import time\nprint('z'*500000,flush=True)\ntime.sleep(60)\n")
    log = Diagnostics(tmp_path/'logs')
    runtime = FrpRuntime(sys.executable,tmp_path/'frp.json',prefix=[str(helper)],verify=False,diagnostics=log)
    await runtime.start({})
    try:
        await asyncio.wait_for(runtime.restart(), 5)
    finally:
        await asyncio.wait_for(runtime.stop(), 5)
    assert not runtime.status()['running']
