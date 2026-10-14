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
@pytest.mark.parametrize('failure', [None, 'vulnerable', 'wrong-image'])
def test_fresh_binary_check_runs_again_despite_existing_build_cache_and_report(tmp_path, monkeypatch, failure, component, binary_name):
    module = checker()
    checks = []
    def run(command, **kwargs):
        if command[:3] == ['docker', 'image', 'inspect']:
            config = CONFIG if failure != 'wrong-image' else 'sha256:' + '0' * 64
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps([{'Id': config, 'RootFS': {'Layers': CANDIDATE['diff_ids']}}]))
        if command[:2] == ['docker', 'create']:
            assert command[-1] == CONFIG
            return subprocess.CompletedProcess(command, 0, stdout='f' * 64 + '\n')
        if command[:2] == ['docker', 'cp']:
            Path(command[-1]).write_bytes(BINARY)
        elif command[:2] == ['docker', 'run']:
            assert '-mode=binary' in command
            assert 'golang.org/x/vuln/cmd/govulncheck@v1.8.0' in command
            assert any('GOVULNDB=https://vuln.go.dev' == arg for arg in command)
            assert command[-1] == '/candidate/' + binary_name
            assert command[command.index('-db') + 1] == 'https://vuln.go.dev'
            mount = command[command.index('-v') + 1]
            assert Path(mount.removesuffix(':/candidate:ro'), binary_name).read_bytes() == BINARY
            checks.append(command)
            kwargs['stdout'].write('fresh actual checker output\n')
            if failure == 'vulnerable':
                raise subprocess.CalledProcessError(3, command)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(module.subprocess, 'run', run)
    output = tmp_path / 'evidence'
    output.mkdir()
    (output/'candidate-go.json').write_text('{"stale":true}')
    if failure:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            module.check(CANDIDATE, component, output)
        assert not (output/'candidate-go.json').exists()
        assert len(checks) == (0 if failure == 'wrong-image' else 1)
    else:
        first = module.check(CANDIDATE, component, output)
        second = module.check(CANDIDATE, component, output)
        assert len(checks) == 2
        assert first['invocation'] != second['invocation']
        assert second['binary_digest'] == 'sha256:' + hashlib.sha256(BINARY).hexdigest()
        assert second['config_digest'] == CONFIG
        assert json.loads((output/'candidate-go.json').read_text()) == second
