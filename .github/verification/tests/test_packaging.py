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
    assert workflow['permissions']=={'contents':'read','packages':'write'}
    build=workflow['jobs']['build']
    assert build['strategy']['matrix']['arch']==['amd64']
    for step in build['steps']:
        if 'uses' in step:
            assert len(step['uses'].split('@')[1])==40
    assert not (output/'client').exists()


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
