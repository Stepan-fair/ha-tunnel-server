import hashlib
import importlib
import json
from pathlib import Path
import subprocess

import pytest

CONFIG = 'sha256:' + 'a' * 64
CANDIDATE = {'config_digest': CONFIG, 'diff_ids': ['sha256:' + 'b' * 64],
             'index_digest': 'sha256:' + 'c' * 64, 'revision': 'd' * 40}
BINARY = b'\x7fELF' + b'bounded synthetic Go binary'

def checker():
    assert Path('tools/check_candidate_go.py').exists(), 'Fresh exact-candidate Go gate missing'
    return importlib.import_module('tools.check_candidate_go')

@pytest.mark.parametrize('component,binary_name', [('server','frps'), ('client','frpc')])
@pytest.mark.parametrize('failure', [None, 'vulnerable', 'unreadable', 'missing-copy', 'wrong-image'])
def test_fresh_binary_check_runs_again_despite_existing_build_cache_and_report(tmp_path, monkeypatch, failure, component, binary_name):
    module = checker()
    checks = []
    removed = []
    copied = []
    production = tmp_path / 'production-binary'
    production.write_bytes(BINARY)
    production.chmod(0o600)
    production_mode = production.stat().st_mode
    def run(command, **kwargs):
        if command[:3] == ['docker', 'image', 'inspect']:
            config = CONFIG if failure != 'wrong-image' else 'sha256:' + '0' * 64
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps([{'Id': config, 'RootFS': {'Layers': CANDIDATE['diff_ids']}}]))
        if command[:2] == ['docker', 'create']:
            assert command[-1] == CONFIG
            return subprocess.CompletedProcess(command, 0, stdout='f' * 64 + '\n')
        if command[:2] == ['docker', 'cp']:
            binary = Path(command[-1])
            if failure != 'missing-copy':
                binary.write_bytes(production.read_bytes())
            copied.append(binary)
        elif command[:2] == ['docker', 'run']:
            assert '-mode=binary' in command
            assert 'golang.org/x/vuln/cmd/govulncheck@v1.8.0' in command
            assert any('GOVULNDB=https://vuln.go.dev' == arg for arg in command)
            assert command[-1] == '/candidate/' + binary_name
            assert command[command.index('-db') + 1] == 'https://vuln.go.dev'
            # A runner-owned 0700 directory is not traversable by the scanner
            # root with ALL capabilities dropped. Bind only the verified file.
            assert '--mount' in command, 'Scanner must bind the binary, not its private parent directory'
            mount = command[command.index('--mount') + 1]
            assert mount == 'type=bind,src=' + str(copied[-1].resolve()) + ',dst=/candidate/' + binary_name + ',readonly'
            assert copied[-1].is_file() and copied[-1].read_bytes() == BINARY
            assert copied[-1].stat().st_mode & 0o222 == 0
            if __import__('os').name == 'posix':
                assert copied[-1].parent.stat().st_mode & 0o777 == 0o700
                assert copied[-1].stat().st_mode & 0o777 == 0o444
            assert '-v' not in command and '--cap-add' not in command and '--privileged' not in command
            assert command[command.index('--cap-drop') + 1] == 'ALL'
            assert command[command.index('--security-opt') + 1] == 'no-new-privileges'
            assert command[command.index('--memory') + 1] == '768m'
            assert command[command.index('--cpus') + 1] == '2'
            assert command[command.index('--pids-limit') + 1] == '256'
            checks.append(command)
            kwargs['stdout'].write('fresh actual checker output\n')
            if failure in ('vulnerable', 'unreadable'):
                if failure == 'unreadable': kwargs['stdout'].write('binary is not a file\n')
                raise subprocess.CalledProcessError(3 if failure == 'vulnerable' else 1, command)
        elif command[:3] == ['docker', 'rm', '-f']:
            removed.append(command[-1])
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(module.subprocess, 'run', run)
    output = tmp_path / 'evidence'
    output.mkdir()
    (output/'candidate-go.json').write_text('{"stale":true}')
    if failure:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            module.check(CANDIDATE, component, output)
        assert not (output/'candidate-go.json').exists()
        assert len(checks) == (0 if failure in ('wrong-image', 'missing-copy') else 1)
    else:
        first = module.check(CANDIDATE, component, output)
        second = module.check(CANDIDATE, component, output)
        assert len(checks) == 2
        assert first['invocation'] != second['invocation']
        assert second['binary_digest'] == 'sha256:' + hashlib.sha256(BINARY).hexdigest()
        assert second['config_digest'] == CONFIG
        assert json.loads((output/'candidate-go.json').read_text()) == second

    if failure != 'wrong-image':
        assert 'f' * 64 in removed
        assert sum(name.startswith('ha-tunnel-go-') for name in removed) == (2 if failure is None else 1)
        assert all(not binary.exists() for binary in copied)
    assert production.read_bytes() == BINARY
    assert production.stat().st_mode == production_mode
