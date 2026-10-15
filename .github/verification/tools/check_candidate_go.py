"""Fresh linked-symbol check of the already verified candidate binary.

Cached frp-builder reports are historical evidence only. Every invocation
extracts the exact verified image binary and runs a new pinned Go scanner
container against the current vendor database, without scanner cache mounts.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

if __package__:
    from tools.oci_candidate import hash_stream, read_json, read_json_file, require, verify, verify_smoke
else:
    from oci_candidate import hash_stream, read_json, read_json_file, require, verify, verify_smoke

GO_IMAGE = 'golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c'
CHECKER = 'golang.org/x/vuln/cmd/govulncheck@v1.8.0'
DATABASE = 'https://vuln.go.dev'


def check(candidate, component, output):
    require(component in ('server', 'client'), 'Invalid component')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    evidence = output / 'candidate-go.json'
    evidence.unlink(missing_ok=True)  # Failed rechecks must not retain old success.
    binary_name = 'frps' if component == 'server' else 'frpc'
    result = subprocess.run(['docker', 'image', 'inspect', candidate['config_digest']],
                            check=True, capture_output=True, text=True, timeout=30)
    inspected = read_json(result.stdout.encode('utf-8'))
    require(isinstance(inspected, list) and len(inspected) == 1, 'Invalid candidate inspection')
    verify_smoke(candidate, inspected[0])
    started = datetime.now(timezone.utc).isoformat()
    with tempfile.TemporaryDirectory(prefix='ha-tunnel-go-') as directory:
        result = subprocess.run(['docker', 'create', '--network', 'none', '--entrypoint', '/bin/true',
                                 candidate['config_digest']], check=True, capture_output=True, text=True, timeout=30)
        container = result.stdout.strip()
        require(re.fullmatch(r'[0-9a-f]{64}', container) is not None, 'Invalid extraction container')
        scanner = 'ha-tunnel-go-' + uuid.uuid4().hex
        try:
            binary = Path(directory) / binary_name
            subprocess.run(['docker', 'cp', container + ':/usr/local/bin/' + binary_name, str(binary)],
                           check=True, timeout=60)
            require(binary.is_file() and not binary.is_symlink() and binary.stat().st_size <= 128 * 1024**2,
                    'Invalid production binary')
            with binary.open('rb') as stream:
                require(stream.read(4) == b'\x7fELF', 'Expected production ELF binary')
                stream.seek(0)
                binary_digest = hash_stream(stream)
            # Keep the host parent private (0700). A capability-free scanner
            # cannot traverse that runner-owned directory; bind only the file.
            # Normalize permissions on this disposable copy, never the image.
            binary.chmod(0o444)
            with (output / (binary_name + '-vulncheck.txt')).open('w', encoding='utf-8') as report:
                # Text mode retains nonzero exit for reachable vulnerabilities.
                subprocess.run([
                    'docker', 'run', '--rm', '--name', scanner, '--memory', '768m', '--cpus', '2', '--pids-limit', '256',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '-e', 'GOTOOLCHAIN=local', '-e', 'GOMAXPROCS=2',
                    '-e', 'GOPROXY=https://proxy.golang.org', '-e', 'GOSUMDB=sum.golang.org',
                    '-e', 'GOVULNDB=' + DATABASE,
                    '--mount', 'type=bind,src=' + str(binary.resolve()) + ',dst=/candidate/' + binary_name + ',readonly',
                    GO_IMAGE,
                    'go', 'run', CHECKER, '-mode=binary', '-db', DATABASE, '-show', 'verbose', '/candidate/' + binary_name,
                ], check=True, stdout=report, stderr=subprocess.STDOUT, timeout=600)
        finally:
            # A client timeout does not stop the daemon-side scanner container.
            subprocess.run(['docker', 'rm', '-f', scanner], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            subprocess.run(['docker', 'rm', '-f', container], check=True, timeout=30)
    result = {'invocation': uuid.uuid4().hex, 'started_at': started,
              'completed_at': datetime.now(timezone.utc).isoformat(),
              'revision': candidate['revision'], 'index_digest': candidate['index_digest'],
              'config_digest': candidate['config_digest'], 'binary': binary_name,
              'binary_digest': binary_digest, 'checker': CHECKER, 'go_image': GO_IMAGE,
              'database': DATABASE}
    evidence.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--component', choices=('server', 'client'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    candidate = verify(args.archive, args.revision, args.version)
    require(candidate == read_json_file(args.record), 'Candidate changed since verification')
    print(json.dumps(check(candidate, args.component, args.output), indent=2))


if __name__ == '__main__':
    main()
