"""Resolve and validate a fresh scan of the latest published role image."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.request import Request, urlopen

if __package__:
    from tools.check_image_scan import check
else:
    from check_image_scan import check

DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect_registry(reference):
    return subprocess.check_output(['skopeo', 'inspect', '--raw', 'docker://' + reference], timeout=60)


def release_tag(role, release):
    require(role in ('server', 'client'), 'Invalid role')
    require(isinstance(release, dict) and release.get('draft') is False and
            release.get('prerelease') is False, 'Expected a published stable release')
    tag = release.get('tag_name')
    require(isinstance(tag, str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag), 'Invalid release tag')
    return tag


def load_candidate(role, release, request=urlopen, *, output=None):
    tag = release_tag(role, release)
    name = role + '-candidate.json'
    assets = release.get('assets')
    require(isinstance(assets, list), 'Missing release assets')
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get('name') == name]
    require(len(matches) == 1, 'Missing or ambiguous release candidate record')
    asset = matches[0]
    url = f'https://github.com/Stepan-fair/ha-tunnel-{role}/releases/download/{tag}/{name}'
    require(asset.get('browser_download_url') == url, 'Unexpected release asset URL')
    size, expected = asset.get('size'), asset.get('digest')
    require(type(size) is int and 0 < size <= 2*1024*1024 and
            isinstance(expected, str) and DIGEST.fullmatch(expected), 'Invalid release asset metadata')
    with request(Request(url, headers={'User-Agent': 'ha-tunnel-security-scan'}), timeout=30) as response:
        raw = response.read(size + 1)
    require(len(raw) == size and 'sha256:' + hashlib.sha256(raw).hexdigest() == expected,
            'Release asset digest mismatch')
    if output is not None:
        Path(output).write_bytes(raw)
    return json.loads(raw)


def resolve_target(role, release, candidate, inspect=inspect_registry):
    tag = release_tag(role, release)
    require(isinstance(candidate, dict) and candidate.get('version') == tag[1:] and
            candidate.get('platform') == 'linux/amd64', 'Release candidate version/platform mismatch')
    image = f'ghcr.io/stepan-fair/ha-tunnel-{role}-amd64'
    raw = inspect(image + ':' + tag[1:])
    index = json.loads(raw)
    require(isinstance(index, dict) and isinstance(index.get('manifests'), list), 'Expected image index')
    manifests = [item for item in index['manifests'] if isinstance(item, dict) and
                 item.get('platform', {}).get('os') == 'linux' and
                 item.get('platform', {}).get('architecture') == 'amd64']
    require(len(manifests) == 1, 'Expected exactly one linux/amd64 manifest')
    digest = manifests[0].get('digest')
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), 'Invalid manifest digest')
    manifest_raw = inspect(image + '@' + digest)
    require('sha256:' + hashlib.sha256(manifest_raw).hexdigest() == digest, 'Manifest digest mismatch')
    manifest = json.loads(manifest_raw)
    config = manifest.get('config', {}).get('digest')
    require(isinstance(config, str) and DIGEST.fullmatch(config), 'Invalid config digest')
    index_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    require(candidate.get('index_digest') == index_digest and candidate.get('manifest_digest') == digest and
            candidate.get('config_digest') == config, 'Registry digest differs from saved release candidate')
    return {'role': role, 'version': tag[1:], 'image': image + '@' + digest,
            'index_digest': index_digest,
            'manifest_digest': digest, 'config_digest': config}


def validate_report(target, report, *, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        descriptor = report['descriptor']
        db = descriptor['db']
        require(descriptor['name'] == 'grype' and not db.get('error') and
                db['status']['valid'] is True, 'Invalid scan database')
        built = datetime.fromisoformat(db['status']['built'].replace('Z', '+00:00'))
        require(built.tzinfo is not None and timedelta(hours=-1) <= now-built <= timedelta(hours=48),
                'Scan database must be at most 48 hours old and not in the future')
        source = report['source']
        require(source['type'] == 'image' and source['target']['imageID'] == target['config_digest'] and
                source['target']['manifestDigest'] == target['manifest_digest'], 'Scan image identity mismatch')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Missing or malformed scan evidence') from error
    return check(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('resolve', 'check'))
    parser.add_argument('--role', choices=('server', 'client'))
    parser.add_argument('--release', type=Path)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--scan', type=Path)
    args = parser.parse_args()
    if args.command == 'resolve':
        require(args.release is not None, 'Release metadata is required')
        release = json.loads(args.release.read_text(encoding='utf-8'))
        candidate = load_candidate(args.role, release, output=args.target.with_name('release-candidate.json'))
        target = resolve_target(args.role, release, candidate)
        args.target.write_text(json.dumps(target, indent=2) + '\n', encoding='utf-8')
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
                output.write('image=' + target['image'] + '\n')
        print(target['image'])
    else:
        require(args.scan is not None, 'Scan report is required')
        target = json.loads(args.target.read_text(encoding='utf-8'))
        report = json.loads(args.scan.read_text(encoding='utf-8'))
        status = 'FAIL'
        details = ''
        try:
            unfixed = validate_report(target, report)
            status = 'PASS'
            details = 'Unfixed High/Critical requiring review: ' + (', '.join(unfixed) or 'none')
        except ValueError as error:
            details = str(error)
            raise
        finally:
            summary = '# Published image scan: ' + status + '\n\n' + target['image'] + '\n\n' + details + '\n'
            args.target.with_name('summary.md').write_text(summary, encoding='utf-8')
            if os.environ.get('GITHUB_STEP_SUMMARY'):
                with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as output:
                    output.write(summary)
        print(details)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
