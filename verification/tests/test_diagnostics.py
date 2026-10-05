import errno
import json
import pytest
from shared.diagnostics import Diagnostics


def test_failure_survives_restart(tmp_path):
    log = Diagnostics(tmp_path)
    try:
        try:
            raise OSError(errno.ENOSPC, 'private-token')
        except OSError as cause:
            raise RuntimeError('secret-password') from cause
    except RuntimeError as error:
        log.failure('startup_error', error, component='storage')
    restored = Diagnostics(tmp_path)
    failure = restored.snapshot()['last_failure']
    assert failure['code'] == 'startup_error'
    assert failure['error']['causes'][1]['errno'] == errno.ENOSPC
    assert failure['error']['causes'][0]['frames'][-1]['function'] == 'test_failure_survives_restart'
    assert failure['error']['causes'][0]['frames'][-1]['line'] > 0
    assert restored.snapshot()['previous_unclean']


def test_primary_error_survives_cleanup_error(tmp_path):
    log = Diagnostics(tmp_path)
    log.failure('startup_error', ValueError('primary-secret'), component='server')
    log.failure('cleanup_error', RuntimeError('second-secret'), component='gateway')
    assert log.snapshot()['last_failure']['code'] == 'startup_error'
    assert len(log.page()['items']) >= 3


def test_disk_failure_console_fallback(tmp_path, capsys):
    blocker = tmp_path/'blocked'
    blocker.write_text('file')
    log = Diagnostics(blocker)
    log.failure('startup_error', OSError(errno.EACCES, 'password'), component='storage')
    output = capsys.readouterr().out
    assert 'startup_error' in output and 'logging_unavailable' in output
    assert 'password' not in output
    assert log.snapshot()['last_failure']['error']['causes'][0]['errno'] == errno.EACCES


def test_rotation_total_bound(tmp_path):
    log = Diagnostics(tmp_path, max_bytes=800, file_count=5)
    for n in range(100):
        log.event('phase', component='server', fields={'count':n})
    files = list(tmp_path.glob('events.jsonl*'))
    assert len(files) == 5 and sum(p.stat().st_size for p in files) <= 4000
    items = log.page(limit=5)['items']
    assert len(items) == 5
    older = log.page(before=items[-1]['id'], limit=5)['items']
    assert not {r['id'] for r in older} & {r['id'] for r in items}


def test_no_secrets_in_any_sink(tmp_path, capsys):
    log = Diagnostics(tmp_path)
    secret = 'SYNTHETIC-private-token-123'
    try:
        raise ValueError(secret + '\nAuthorization: Bearer secret\n-----BEGIN PRIVATE KEY-----')
    except ValueError as error:
        log.failure('startup_error', error, component='server')
    log.event(secret, component=secret, fields={'request':secret,'exit_code':secret,'reason':secret})
    exported = b''.join(log.export()).decode()
    text = ''.join(p.read_text() for p in tmp_path.iterdir() if p.is_file())
    assert secret not in text + exported + capsys.readouterr().out
    assert 'PRIVATE KEY' not in exported and 'Authorization' not in exported


@pytest.mark.parametrize('kwargs', [{'limit':0},{'limit':1001},{'before':'../secret'},{'since':float('nan')},{'level':'secret'},{'component':'unknown'}])
def test_invalid_filters_rejected(tmp_path, kwargs):
    with pytest.raises(ValueError):
        Diagnostics(tmp_path).page(**kwargs)


def test_normal_shutdown_is_distinct_from_power_loss(tmp_path):
    log = Diagnostics(tmp_path)
    log.shutdown()
    other = Diagnostics(tmp_path)
    assert not other.snapshot()['previous_unclean']


def test_startup_failure_records_phase_and_cause(tmp_path):
    import asyncio
    import server.app.main as main
    from pathlib import Path
    original = main.Path
    class Redirect(Path):
        def __new__(cls, value):
            return original(tmp_path/'missing.json') if str(value)=='/data/options.json' else original(value)
    log = Diagnostics(tmp_path/'logs')
    old_path, old_diag = main.Path, getattr(main,'diagnostics',None)
    main.Path, main.diagnostics = Redirect, log
    try:
        with pytest.raises(FileNotFoundError):
            asyncio.run(main.main())
    finally:
        main.Path, main.diagnostics = old_path, old_diag
    failure = log.snapshot()['last_failure']
    assert failure['code']=='startup_error' and failure['fields']['phase']=='load_options'
    assert failure['error']['causes'][0]['errno']==errno.ENOENT


def test_setup_mode_exposes_diagnostics_to_verified_admin(tmp_path):
    import asyncio
    from aiohttp.test_utils import TestClient, TestServer
    from server.app.setup import SetupService, make_setup_app
    service = SetupService(tmp_path,None)
    service.diagnostics = Diagnostics(tmp_path/'logs')
    async def scenario():
        async def admin(user): return user=='admin'
        async with TestClient(TestServer(make_setup_app(service,admin,ingress_ips=['127.0.0.1']))) as client:
            assert (await client.get('/api/diagnostics',headers={'X-Remote-User-Id':'admin'})).status==200
    asyncio.run(scenario())


async def test_background_exception_is_observed(tmp_path):
    import asyncio
    log = Diagnostics(tmp_path)
    async def broken():
        raise RuntimeError('private-key')
    task = asyncio.create_task(broken())
    log.observe(task,'telemetry')
    await asyncio.gather(task,return_exceptions=True)
    await asyncio.sleep(0)
    assert log.snapshot()['last_failure']['component']=='telemetry'
    assert 'private-key' not in b''.join(log.export()).decode()


def test_sqlite_failure_retains_native_code(tmp_path):
    import sqlite3
    log = Diagnostics(tmp_path/'logs')
    with sqlite3.connect(tmp_path/'db.sqlite') as db:
        db.execute('create table t (id integer primary key)')
        db.execute('insert into t values (1)')
        try:
            db.execute('insert into t values (1)')
        except sqlite3.Error as error:
            log.failure('storage_error',error,component='storage')
    cause = log.snapshot()['last_failure']['error']['causes'][0]
    assert cause['reason']=='database_error' and cause['sqlite_errorcode']>0


def test_diagnostics_menu_is_safe_and_available_in_setup():
    from pathlib import Path
    html = Path('server/app/templates/index.html').read_text(encoding='utf-8')
    script = Path('server/app/templates/app.js').read_text(encoding='utf-8')
    assert 'data-tab="diagnostics"' in html
    assert 'api/diagnostics/export' in script and 'loadDiagnostics' in script
    assert 'innerHTML' not in script


async def test_unhandled_loop_error_never_uses_raw_context(tmp_path,capsys):
    import asyncio
    log=Diagnostics(tmp_path)
    loop=asyncio.get_running_loop()
    previous=loop.get_exception_handler()
    log.install_loop(loop)
    try:
        loop.call_exception_handler({'message':'private-token','exception':RuntimeError('private-token')})
    finally:
        loop.set_exception_handler(previous)
    assert 'private-token' not in capsys.readouterr().out
    assert log.snapshot()['last_failure']['code']=='service_error'


def test_even_small_rotation_limit_bounds_large_exception_chain(tmp_path):
    log=Diagnostics(tmp_path,max_bytes=512)
    try:
        try: raise OSError(errno.ENOSPC,'secret')
        except OSError as cause: raise RuntimeError('another-secret') from cause
    except Exception as error:
        log.failure('startup_error',error,component='server')
    assert all(p.stat().st_size<=512 for p in tmp_path.glob('events.jsonl*'))
