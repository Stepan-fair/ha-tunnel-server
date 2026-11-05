from pathlib import Path
from datetime import datetime, timezone, timedelta
import io
import hashlib
import json
import pytest
from ruamel.yaml import YAML

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
CONFIG = 'sha256:' + 'a' * 64


def resolver_fixture():
    manifest = json.dumps({'schemaVersion': 2, 'config': {'digest': CONFIG}}).encode()
    digest = 'sha256:' + hashlib.sha256(manifest).hexdigest()
    index = json.dumps({'manifests': [{'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': digest}]}).encode()
    calls = []
    def inspect(reference):
        calls.append(reference)
        return index if reference.endswith(':0.5.2') else manifest
    candidate = {'version': '0.5.2', 'platform': 'linux/amd64', 'index_digest': 'sha256:' + hashlib.sha256(index).hexdigest(), 'manifest_digest': digest, 'config_digest': CONFIG}
    return {'tag_name': 'v0.5.2', 'draft': False, 'prerelease': False}, inspect, calls, digest, candidate


@pytest.mark.parametrize('role', ['server', 'client'])
def test_resolve_scans_exact_runtime_digest_of_published_release(role):
    from tools.scan_published_image import resolve_target
    release, inspect, calls, digest, candidate = resolver_fixture()
    target = resolve_target(role, release, candidate, inspect)
    image = f'ghcr.io/stepan-fair/ha-tunnel-{role}-amd64'
    assert target['image'] == image + '@' + digest
    assert target['version'] == '0.5.2' and target['config_digest'] == CONFIG
    assert calls == [image + ':0.5.2', image + '@' + digest]


@pytest.mark.parametrize('change', [{'draft': True}, {'prerelease': True}, {'tag_name': 'latest'}, {'tag_name': 'v0.5.2;echo bad'}, {'tag_name': '../0.5.2'}])
def test_unpublished_or_unsafe_versions_are_rejected_before_registry_access(change):
    from tools.scan_published_image import resolve_target
    release, inspect, calls, _, candidate = resolver_fixture()
    with pytest.raises(ValueError): resolve_target('server', release | change, candidate, inspect)
    assert not calls


def test_changed_manifest_cannot_be_scanned_under_another_digest():
    from tools.scan_published_image import resolve_target
    release, inspect, _, _, candidate = resolver_fixture()
    def corrupt(reference):
        raw = inspect(reference)
        return raw + b' ' if '@' in reference else raw
    with pytest.raises(ValueError, match='digest'): resolve_target('server', release, candidate, corrupt)


def report_fixture():
    target = {'manifest_digest': 'sha256:' + 'b' * 64, 'config_digest': CONFIG}
    report = {'matches': [], 'descriptor': {'name': 'grype', 'db': {'error': None, 'status': {'valid': True, 'built': (NOW-timedelta(hours=2)).isoformat()}}},
              'source': {'type': 'image', 'target': {'imageID': CONFIG, 'manifestDigest': target['manifest_digest']}}}
    return target, report


def test_current_clean_report_and_unfixed_findings_remain_reviewable():
    from tools.scan_published_image import validate_report
    target, report = report_fixture()
    assert validate_report(target, report, now=NOW) == []
    report['matches'] = [{'vulnerability': {'id': 'CVE-synthetic', 'severity': 'Critical', 'fix': {'versions': []}}}]
    assert validate_report(target, report, now=NOW) == ['CVE-synthetic']
    report['matches'][0]['vulnerability']['fix']['versions'] = ['1.2.3']
    with pytest.raises(ValueError, match='Fixable severe'): validate_report(target, report, now=NOW)


@pytest.mark.parametrize('fault', ['old-db', 'future-db', 'missing-db-time', 'db-error', 'invalid-db', 'wrong-manifest', 'wrong-config', 'no-source', 'no-matches'])
def test_invalid_or_stale_scan_fails_closed(fault):
    from tools.scan_published_image import validate_report
    target, report = report_fixture()
    status = report['descriptor']['db']['status']
    if fault == 'old-db': status['built'] = (NOW-timedelta(hours=49)).isoformat()
    elif fault == 'future-db': status['built'] = (NOW+timedelta(hours=2)).isoformat()
    elif fault == 'missing-db-time': status.pop('built')
    elif fault == 'db-error': report['descriptor']['db']['error'] = 'download failed'
    elif fault == 'invalid-db': status['valid'] = False
    elif fault == 'wrong-manifest': report['source']['target']['manifestDigest'] = CONFIG
    elif fault == 'wrong-config': report['source']['target']['imageID'] = 'sha256:' + 'c'*64
    elif fault == 'no-source': report.pop('source')
    elif fault == 'no-matches': report.pop('matches')
    with pytest.raises(ValueError): validate_report(target, report, now=NOW)


@pytest.mark.parametrize('role', ['server', 'client'])
def test_generated_daily_scan_is_read_only_and_preserves_failed_reports(tmp_path, role):
    from tools.release_repository import release_repository
    output = tmp_path/role
    release_repository(role, output)
    path = output/'.github/workflows/published-image-scan.yml'
    assert path.is_file(), 'Published releases are not periodically rescanned'
    text = path.read_text()
    flow = YAML(typ='safe').load(text)
    assert flow['on']['schedule'] == [{'cron': '37 4 * * *'}]
    assert 'workflow_dispatch' in flow['on']
    assert flow['permissions'] == {'contents': 'read'}
    assert all('write' not in job.get('permissions', {}).values() for job in flow['jobs'].values())
    steps = flow['jobs']['scan']['steps']
    assert any('releases/latest' in step.get('run', '') for step in steps)
    scan = next(step for step in steps if 'registry:' in step.get('run', ''))
    assert 'GRYPE_DB_AUTO_UPDATE=true' in scan['run'] and 'GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h' in scan['run']
    assert '--only-fixed' not in scan['run'] and 'continue-on-error' not in scan
    assert f'--role {role}' in text and '__ROLE__' not in text
    upload = next(step for step in steps if step.get('uses', '').startswith('actions/upload-artifact@'))
    assert upload['if'] == 'always()' and upload['with']['retention-days'] == 30
    assert (output/'.github/verification/tools/scan_published_image.py').is_file()
    assert not (output/role/'tools/scan_published_image.py').exists()


def test_production_and_linux_test_builds_require_fixed_nginx():
    for path in ('server/Dockerfile', 'tools/Dockerfile.test'):
        text = Path(path).read_text()
        assert 'dpkg --compare-versions' in text and 'ge 1.26.3-3+deb13u10' in text


@pytest.mark.parametrize('field', ['version', 'platform', 'index_digest', 'manifest_digest', 'config_digest'])
def test_registry_cannot_drift_from_saved_release_candidate(field):
    from tools.scan_published_image import resolve_target
    release, inspect, _, _, candidate = resolver_fixture()
    candidate[field] = 'sha256:' + 'f'*64 if field.endswith('digest') else 'wrong'
    with pytest.raises(ValueError): resolve_target('server', release, candidate, inspect)


@pytest.mark.parametrize('role', ['server', 'client'])
def test_release_evidence_is_downloaded_from_exact_tag_and_hash_verified(role, tmp_path):
    from tools.scan_published_image import load_candidate
    release, _, _, _, candidate = resolver_fixture()
    raw = (json.dumps(candidate, separators=(',', ':')) + '\n\n').encode()
    url = f'https://github.com/Stepan-fair/ha-tunnel-{role}/releases/download/v0.5.2/{role}-candidate.json'
    release['assets'] = [{'name': f'{role}-candidate.json', 'browser_download_url': url,
                          'size': len(raw), 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}]
    seen = []
    def request(value, **kwargs):
        seen.append(value.full_url)
        return io.BytesIO(raw)
    saved = tmp_path/'release-candidate.json'
    assert load_candidate(role, release, request, output=saved) == candidate
    assert saved.read_bytes() == raw
    assert seen == [url]
    release['assets'][0]['digest'] = 'sha256:' + 'f'*64
    with pytest.raises(ValueError, match='digest'): load_candidate(role, release, request)
    release['assets'][0]['browser_download_url'] = 'https://example.org/untrusted'
    with pytest.raises(ValueError): load_candidate(role, release, request)
    assert len(seen) == 2


def test_missing_release_record_does_not_fall_back_to_mutable_tag():
    from tools.scan_published_image import load_candidate
    release, _, _, _, _ = resolver_fixture()
    release['assets'] = []
    with pytest.raises(ValueError): load_candidate('server', release)
