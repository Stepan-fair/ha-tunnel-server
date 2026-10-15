import importlib.util
from pathlib import Path
import pytest
from ruamel.yaml import YAML


def test_two_self_contained_packages_without_runtime_data(tmp_path):
    from tools.package import package
    output=tmp_path/'repo'
    package(output)
    yaml=YAML(typ='safe')
    for component in ('server','client'):
        root=output/component
        config=yaml.load((root/'config.yaml').read_text())
        assert config['arch']==['amd64']
        assert config['ingress'] and config['panel_admin']
        assert config['services']==['mqtt:want']
        assert not config.get('full_access') and not config.get('docker_api') and not config.get('privileged')
        assert (root/'shared/protocol.py').read_bytes()==Path('shared/protocol.py').read_bytes()
        assert (root/component/'app/main.py').exists()
        assert 'latest' not in (root/'Dockerfile').read_text()
        assert '@sha256:' in (root/'Dockerfile').read_text()
        assert (root/'requirements.lock').exists()
        for p in root.rglob('*'):
            assert p.suffix not in ('.key','.pem','.db','.pyc')
            assert p.name not in ('.venv','__pycache__','options.json','credentials.json')
    server=yaml.load((output/'server/config.yaml').read_text())
    assert set(server['ports'])=={'7000/tcp'}
    assert not server.get('host_network')
    client=yaml.load((output/'client/config.yaml').read_text())
    assert client['host_network'] and client['hassio_role']=='homeassistant'
    assert (output/'repository.yaml').exists()


@pytest.mark.parametrize('role',['server','client'])
def test_canonical_notification_asset_in_standalone_role_http(tmp_path,role):
    import os,subprocess,sys
    from tools.package import package
    output=tmp_path/'repository'; package(output,component=role)
    root=output/role; asset=root/'shared/notification_settings.js'
    assert asset.is_file(), 'Standalone package must include canonical shared notification asset'
    assert asset.read_bytes()==Path('shared/notification_settings.js').read_bytes()
    assert not (root/role/'app/templates/notification_settings.js').exists()
    script='''
import asyncio,sys,tempfile
from pathlib import Path
from aiohttp.test_utils import TestClient,TestServer
async def main():
    role=sys.argv[1]
    options={'ingress_ips':['127.0.0.1'],'admin_user_ids':['admin']}
    async def admin(user): return user=='admin'
    async def disconnect(cid): pass
    with tempfile.TemporaryDirectory() as temporary:
        if role=='server':
            from server.app.store import Store
            from server.app.web import make_ingress_app
            from server.app.setup import SetupService,make_setup_app
            store=Store(Path(temporary)/'state.db','example.org',clock=lambda:1000000)
            apps=[make_ingress_app(store,None,options,disconnect),
                  make_setup_app(SetupService(Path(temporary)/'setup',object()),admin,ingress_ips=['127.0.0.1'])]
        else:
            from client.app.web import make_app
            apps=[make_app(object(),options)]
        assert Path(sys.modules[role+'.app.web'].__file__).resolve().is_relative_to(Path.cwd())
        assert Path(sys.modules['shared.notifications'].__file__).resolve().is_relative_to(Path.cwd())
        for app in apps:
            async with TestClient(TestServer(app)) as client:
                response=await client.get('/notification_settings.js',headers={'X-Remote-User-Id':'admin'})
                assert response.status==200
                assert await response.read()==Path('shared/notification_settings.js').read_bytes()
                assert response.content_type=='text/javascript'
asyncio.run(main())
'''
    env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
    result=subprocess.run([sys.executable,'-c',script,role],cwd=root,env=env,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr


def test_gateway_trust_and_header_normalization():
    from server.app.gateway import nginx_config
    text=nginx_config(['172.30.33.5'])
    assert 'allow 172.30.33.5;' in text and 'deny all;' in text
    assert 'proxy_set_header X-Forwarded-For $http_x_real_ip;' in text
    assert '$proxy_add_x_forwarded_for' not in text
    assert 'proxy_pass http://127.0.0.1:18081;' in text
    assert 'access_log off;' in text
    with pytest.raises(ValueError): nginx_config(['0.0.0.0/0'])
    with pytest.raises(ValueError): nginx_config(['127.0.0.1; allow all'])


@pytest.mark.parametrize('role,other',[('server','client'),('client','server')])
def test_independent_role_repository(tmp_path,role,other):
    from tools.package import package
    output=tmp_path/role
    package(output,component=role)
    assert (output/role/'config.yaml').exists() and not (output/other).exists()
    text=(output/'repository.yaml').read_text(encoding='utf-8')
    assert 'https://github.com/Stepan-fair/ha-tunnel-'+role in text
    assert (output/'README.md').read_bytes()==Path('docs/'+role.upper()+'_INSTALL.md').read_bytes()
    assert (output/role/'DOCS.md').read_bytes()==Path('docs/'+role.upper()+'_INSTALL.md').read_bytes()
    assert (output/role/'shared/presentation.py').read_bytes()==Path('shared/presentation.py').read_bytes()
    assert not any(p.name in ('options.json','credentials.json','.tools','PROGRESS.md') for p in output.rglob('*'))
    if role=='server':
        yaml=YAML(typ='safe'); options=yaml.load((output/role/'config.yaml').read_text())['options']
        assert options['base_domain']==options['server_url']==options['npm_host']==''
    with pytest.raises(ValueError): package(output,component=role)


def test_role_release_workflow_has_scoped_permissions(tmp_path):
    from tools.release_repository import release_repository
    output=tmp_path/'release'
    release_repository('server',output)
    yaml=YAML(typ='safe')
    workflow=yaml.load((output/'.github/workflows/build.yml').read_text())
    assert workflow['permissions']=={'contents':'read'}
    build=workflow['jobs']['build']
    assert build['strategy']['matrix']['arch']==['amd64']
    for step in build['steps']:
        if 'uses' in step:
            assert len(step['uses'].split('@')[1])==40
    assert not (output/'client').exists()


def test_generated_acceptance_and_baseline_do_not_enter_production_context(tmp_path):
    from tools.release_repository import release_repository
    output=tmp_path/'release';release_repository('client',output)
    workflow=YAML(typ='safe').load((output/'.github/workflows/build.yml').read_text())
    steps=workflow['jobs']['security-tests']['steps']
    checkout=next(s for s in steps if s.get('with',{}).get('path')=='performance-baseline')
    assert checkout['with']['ref']=='dce6378b7175ca30ee0d1bff68c27b74ba3c9a77'
    assert checkout['with']['persist-credentials'] is False
    build_index=next(i for i,s in enumerate(steps) if 'docker build ' in s.get('run',''))
    assert build_index<steps.index(checkout)
    production=workflow['jobs']['build']
    assert production['steps'][0]['uses'].startswith('actions/checkout@')
    assert all(s.get('with',{}).get('path')!='performance-baseline' for s in production['steps'])
    measurement=next(s['run'] for s in steps if 'frp_performance.py' in s.get('run',''))
    for required in ('--network none','--memory 768m','--cpus 2','--pids-limit 256',':/baseline:ro','trap ','timeout --kill-after=10s 150s'):
        assert required in measurement
    external=YAML(typ='safe').load((output/'.github/workflows/external_acceptance.yml').read_text())
    assert set(external['on'])=={'workflow_dispatch'} and external['permissions']=={'contents':'read'}
    check=external['jobs']['check']['steps'][-1]
    assert check['env']=={'HA_TUNNEL_ACCEPTANCE_ORIGINS':'${{ secrets.HA_TUNNEL_ACCEPTANCE_ORIGINS }}'}
    assert '-m tools.external_acceptance' in check['run'] and 'echo' not in check['run']
    assert not (output/'client/tools/external_acceptance.py').exists()
    assert (output/'.github/verification/tools/external_acceptance.py').is_file()
    for name in ('UPGRADE_050.md','SECURITY_ASSESSMENT_050.md','SECURITY_FINDINGS_050.csv'):
        assert (output/'docs'/name).read_bytes()==(Path('docs')/name).read_bytes()


def test_release_runs_real_linux_tests_before_publication(tmp_path):
    from tools.release_repository import release_repository
    output=tmp_path/'release'
    release_repository('server',output)
    workflow=YAML(typ='safe').load((output/'.github/workflows/build.yml').read_text())
    assert workflow['jobs']['build']['needs']=='security-tests'
    assert workflow['jobs']['security-tests']['permissions']=={'contents':'read'}
    assert (output/'.github/verification/tests/test_security_hardening.py').exists()
    assert (output/'.github/verification/tools/Dockerfile.test').exists()
    assert not any(p.name in ('PROGRESS.md','credentials.json','AGENTS.md','.tools') for p in output.rglob('*'))
    build_step=next(s for s in workflow['jobs']['build']['steps'] if s.get('uses','').startswith('docker/build-push-action@'))
    assert build_step['with']['sbom'] is True
    assert build_step['with']['provenance']=='mode=max'
    assert build_step['with']['push'] is False
    assert build_step['with']['outputs']=='type=oci,dest=candidate.tar'
    assert 'if' not in workflow['jobs']['build']
    assert len([s for job in workflow['jobs'].values() for s in job['steps']
                if s.get('uses','').startswith('docker/build-push-action@')]) == 1
    node_steps = [s for s in workflow['jobs']['security-tests']['steps'] if s.get('run', '').startswith('node ')]
    assert {s['run'].split('/')[-1] for s in node_steps} == {
        'command_id.test.cjs', 'billing_overview.test.cjs', 'transfer_dialog.test.cjs',
        'clock_repair_ui.test.cjs', 'dependency_status_ui.test.cjs', 'notification_settings.test.cjs'}
    assert all(s.get('working-directory') == '.github/verification' for s in node_steps)


def test_release_cli_is_directly_executable(tmp_path):
    import subprocess,sys
    result=subprocess.run([sys.executable,'tools/release_repository.py','--component','client','--output',str(tmp_path/'cli')],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert (tmp_path/'cli/.github/workflows/build.yml').exists()


def test_release_gate_rejects_modified_or_extra_production_files(tmp_path):
    from tools.release_repository import release_repository
    from tools.verify_release_context import verify_release_context
    output=tmp_path/'release'
    release_repository('server',output)
    verify_release_context(output,'server')
    assert (output/'.gitattributes').read_text()=='* text eol=lf\n'
    source=output/'server/server/app/web.py'
    original=source.read_bytes()
    source.write_bytes(original+b'\n# production-only change\n')
    with pytest.raises(ValueError,match='Production context differs'):
        verify_release_context(output,'server')
    source.write_bytes(original)
    (output/'server/credentials.json').write_text('{}')
    with pytest.raises(ValueError,match='Production context differs'):
        verify_release_context(output,'server')


@pytest.mark.parametrize('role', ['server', 'client'])
def test_role_release_exposes_only_requested_application(tmp_path, role):
    from tools.release_repository import release_repository
    output = tmp_path / 'repository'
    release_repository(role, output)
    # Supervisor scans recursively, excluding dot directories and rootfs.
    visible = sorted(
        path.relative_to(output).as_posix()
        for path in output.glob('**/config.*')
        if path.suffix in ('.yaml', '.yml', '.json')
        and not any(part.startswith('.') or part == 'rootfs'
                    for part in path.relative_to(output).parts)
    )
    assert visible == [f'{role}/config.yaml']


@pytest.mark.parametrize('config_name', ['config.yaml', 'config.yml', 'config.json'])
def test_release_gate_rejects_extra_discoverable_configs(tmp_path, config_name):
    from tools.release_repository import release_repository
    from tools.verify_release_context import verify_release_context
    output = tmp_path / 'repository'
    release_repository('client', output)
    extra = output / 'samples' / config_name
    extra.parent.mkdir()
    extra.write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='Unexpected discoverable application configuration'):
        verify_release_context(output, 'client')


@pytest.mark.parametrize('role', ['server', 'client'])
def test_generated_repository_executes_candidate_gate_with_saved_record(tmp_path, role):
    import json
    import subprocess
    import sys
    from tools.release_repository import release_repository
    from test_oci_candidate import fixture, scan_report, REVISION, VERSION
    output = tmp_path / 'role'
    release_repository(role, output)
    archive, _, _, config, _, _ = fixture(tmp_path)
    script = output / '.github/verification/tools/oci_candidate.py'
    record = tmp_path / 'candidate.json'
    base = [sys.executable, str(script), '--archive', str(archive), '--revision', REVISION,
            '--version', VERSION, '--record', str(record)]
    result = subprocess.run([*base, 'verify'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    expected = json.loads(record.read_text())
    scan = tmp_path / 'scan.json'
    scan.write_text(json.dumps(scan_report(expected)))
    inspection = tmp_path / 'inspection.json'
    inspection.write_text(json.dumps([{'Id': config['digest'], 'RootFS': {'Layers': expected['diff_ids']}}]))
    result = subprocess.run([*base, 'gate', '--scan', str(scan), '--inspection', str(inspection)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    scan.write_text('{}')
    result = subprocess.run([*base, 'gate', '--scan', str(scan), '--inspection', str(inspection)],
                            capture_output=True, text=True)
    assert result.returncode != 0


def test_only_tag_publisher_has_package_write_and_reuses_candidate_artifacts(tmp_path):
    from tools.release_repository import release_repository
    output = tmp_path / 'release'
    release_repository('server', output)
    workflow = YAML(typ='safe').load((output/'.github/workflows/build.yml').read_text())
    jobs = workflow['jobs']
    assert jobs['build']['permissions'] == {'contents': 'read'}
    assert jobs['security-tests']['permissions'] == {'contents': 'read'}
    for name, job in jobs.items():
        effective = job.get('permissions', workflow['permissions'])
        if effective.get('packages') == 'write':
            assert name == 'publish'
            assert job['if'] == "startsWith(github.ref, 'refs/tags/v')"
            assert job['needs'] == 'build'
    publisher = jobs['publish']
    assert publisher['permissions'] == {'contents': 'read', 'packages': 'write'}
    downloads = [step['with']['name'] for step in publisher['steps']
                 if step.get('uses', '').startswith('actions/download-artifact@')]
    assert set(downloads) == {'server-amd64-candidate-evidence', 'server-amd64-oci-candidate'}
    assert not any(step.get('uses', '').startswith('docker/build-push-action@') for step in publisher['steps'])
    # The executable publish CLI already tests revalidation before any copy.
    assert any('oci_candidate.py publish' in step.get('run', '') for step in publisher['steps'])

def test_failed_verification_preserves_only_bounded_existing_original_archive(tmp_path):
    """Run the generated diagnostic eligibility script after an actual gate failure."""
    import os
    import subprocess
    import sys
    from tools.release_repository import release_repository
    from test_oci_candidate import fixture, REVISION, VERSION
    output = tmp_path / 'release'
    release_repository('server', output)
    workflow = YAML(typ='safe').load((output/'.github/workflows/build.yml').read_text())
    steps = workflow['jobs']['build']['steps']
    guards = [step for step in steps if step.get('id') == 'candidate-archive']
    assert len(guards) == 1, 'Failed candidate archive has no bounded diagnostic eligibility step'
    guard = guards[0]
    upload = next(step for step in steps if step.get('with', {}).get('path') == 'candidate.tar')
    assert guard['if'] == 'always()'
    assert upload['if'] == "always() && steps.candidate-archive.outputs.present == 'true'"
    assert upload['with']['retention-days'] == 7
    assert upload['with']['compression-level'] == 0
    script = guard['run'].removeprefix("python - <<'PY'\n").removesuffix("PY\n")
    archive, *_ = fixture(output, revision='b' * 40)
    before = archive.read_bytes()
    rejected = subprocess.run([sys.executable, str(output/'.github/verification/tools/oci_candidate.py'),
        'verify', '--archive', str(archive), '--revision', REVISION, '--version', VERSION,
        '--record', str(output/'candidate.json')], capture_output=True, text=True)
    assert rejected.returncode != 0
    assert not (output/'candidate.json').exists()
    result_file = output/'diagnostic-output'
    def eligible():
        result_file.unlink(missing_ok=True)
        result = subprocess.run([sys.executable, '-c', script], cwd=output,
            env={**os.environ, 'GITHUB_OUTPUT': str(result_file)}, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return result_file.read_text()
    assert eligible() == 'present=true\n'
    assert archive.read_bytes() == before  # upload original, without rewrite or bypass
    archive.unlink()
    assert eligible() == 'present=false\n'  # pre-build failure must not mask original failure
    archive.mkdir()
    assert eligible() == 'present=false\n'
    archive.rmdir()
    archive.write_bytes(b'')
    assert eligible() == 'present=false\n'
    # Exercise oversized stat without allocating an 8GiB file.
    import stat as stat_module
    oversized = """from types import SimpleNamespace
from pathlib import Path
Path.lstat = lambda self: SimpleNamespace(st_mode=%d, st_size=8*1024**3+1)
""" % stat_module.S_IFREG
    result_file.unlink()
    result = subprocess.run([sys.executable, '-c', oversized + script], cwd=output,
        env={**os.environ, 'GITHUB_OUTPUT': str(result_file)}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result_file.read_text() == 'present=false\n'
    assert workflow['jobs']['publish']['needs'] == 'build'
    assert 'continue-on-error' not in next(step for step in steps if 'oci_candidate.py verify' in step.get('run', ''))


@pytest.mark.parametrize('role', ['server', 'client'])
def test_single_oci_build_has_local_source_name_for_statement_subjects(tmp_path, role):
    from tools.release_repository import release_repository
    output = tmp_path / 'release'
    release_repository(role, output)
    workflow = YAML(typ='safe').load((output / '.github/workflows/build.yml').read_text())
    builds = [step for job in workflow['jobs'].values() for step in job['steps']
              if step.get('uses', '').startswith('docker/build-push-action@')]
    assert len(builds) == 1
    options = builds[0]['with']
    # BuildKit constructs in-toto defaultSubjects from exporter image names.
    # A local source-specific name provides that binding without a registry push.
    assert options.get('tags') == 'ha-tunnel-' + role + '-candidate:${{ github.sha }}'
    assert options['push'] is False
    assert options['outputs'] == 'type=oci,dest=candidate.tar'
    assert options['sbom'] is True and options['provenance'] == 'mode=max'
    assert workflow['jobs']['build']['permissions'] == {'contents': 'read'}
    assert workflow['jobs']['publish']['needs'] == 'build'
