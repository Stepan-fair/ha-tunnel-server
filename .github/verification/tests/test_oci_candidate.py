"""Real OCI graph fixtures; subprocess/network edges only are stubbed."""
import gzip
import hashlib
import importlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import pytest

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
LAYER = 'application/vnd.oci.image.layer.v1.tar+gzip'
ATTEST = 'application/vnd.in-toto+json'
ARTIFACT = 'application/vnd.docker.attestation.manifest.v1+json'
EMPTY = 'application/vnd.oci.empty.v1+json'
REVISION = 'a' * 40
VERSION = '0.4.3'

def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()

def fixture(tmp_path, *, wrap=True, revision=REVISION, platform='amd64', change=None, artifact=False):
    blobs = {}
    def blob(value, media):
        data = value if isinstance(value, bytes) else encoded(value)
        digest = 'sha256:' + hashlib.sha256(data).hexdigest()
        blobs['blobs/sha256/' + digest[7:]] = data
        return {'mediaType': media, 'digest': digest, 'size': len(data)}
    config = blob({'architecture': platform, 'os': 'linux', 'config': {'Labels': {
        'org.opencontainers.image.revision': revision, 'org.opencontainers.image.version': VERSION}},
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(b'filesystem').hexdigest()]}}, CONFIG)
    layer = blob(gzip.compress(b'filesystem', mtime=0), LAYER)
    runnable = blob({'schemaVersion': 2, 'mediaType': MANIFEST, 'config': config, 'layers': [layer]}, MANIFEST)
    runnable['platform'] = {'os': 'linux', 'architecture': platform}
    layers = []
    for kind in ('https://slsa.dev/provenance/v1' if artifact else 'https://slsa.dev/provenance/v0.2',
                 'https://spdx.dev/Document'):
        layers.append(blob({'_type': 'https://in-toto.io/Statement/v1' if artifact else 'https://in-toto.io/Statement/v0.1', 'predicateType': kind,
            'subject': [{'name': 'test', 'digest': {'sha256': runnable['digest'][7:]}}],
            'predicate': {'buildType': 'https://mobyproject.org/buildkit@v1', 'spdxVersion': 'SPDX-2.3'}}, ATTEST))
        layers[-1]['annotations'] = {'in-toto.io/predicate-type': kind}
    # Actual Buildx archives from both roles use this OCI 1.1 artifact structure,
    # including the physical {} blob AND its canonical inline representation.
    if artifact:
        att_config = blob(b'{}', EMPTY)
        att_config['data'] = 'e30='
        document = {'artifactType': ARTIFACT,
                    'subject': {key: runnable[key] for key in ('mediaType', 'digest', 'size')}}
    else:
        att_config = blob({'architecture': 'unknown', 'os': 'unknown',
                           'rootfs': {'type': 'layers', 'diff_ids': []}}, CONFIG)
        document = {}
    attest = blob({'schemaVersion': 2, 'mediaType': MANIFEST, 'config': att_config,
                   'layers': layers, **document}, MANIFEST)
    attest.update(platform={'os': 'unknown', 'architecture': 'unknown'}, annotations={
        'vnd.docker.reference.type': 'attestation-manifest', 'vnd.docker.reference.digest': runnable['digest']})
    index = {'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [runnable, attest]}
    if change: change(blobs, index)
    root = blob(index, INDEX)
    envelope = {'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [root]} if wrap else index
    if not wrap: del blobs['blobs/sha256/' + root['digest'][7:]]
    blobs.update({'index.json': encoded(envelope), 'oci-layout': encoded({'imageLayoutVersion': '1.0.0'})})
    path = tmp_path / 'candidate.tar'
    write_tar(path, blobs.items())
    return path, root, runnable, config, layer, blobs

def write_tar(path, entries):
    with tarfile.open(path, 'w') as archive:
        for name, data in entries:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))

def gate():
    assert Path('tools/oci_candidate.py').is_file(), 'Immutable OCI verification gate is missing'
    return importlib.import_module('tools.oci_candidate')

@pytest.mark.parametrize('artifact', [False, True])
@pytest.mark.parametrize('wrap', [False, True])
def test_verifies_complete_index_and_distinguishes_layout_envelope(tmp_path, wrap, artifact):
    path, root, runnable, config, layer, _ = fixture(tmp_path, wrap=wrap, artifact=artifact)
    result = gate().verify(path, REVISION, VERSION)
    assert result['index_digest'] == root['digest']
    assert result['manifest_digest'] == runnable['digest']
    assert result['config_digest'] == config['digest']
    assert result['layers'] == [layer['digest']]
    assert len(result['attestations']) == 1
    if artifact:
        assert result['descriptors']['sha256:' + hashlib.sha256(b'{}').hexdigest()] == [EMPTY, 2]

@pytest.mark.parametrize('target', ['layer', 'index', 'attestation'])
def test_rejects_replaced_graph_bytes(tmp_path, target):
    path, root, _, _, layer, blobs = fixture(tmp_path)
    digest = {'layer': layer['digest'], 'index': root['digest'],
        'attestation': json.loads(blobs['blobs/sha256/' + root['digest'][7:]])['manifests'][1]['digest']}[target]
    name = 'blobs/sha256/' + digest[7:]
    blobs[name] = b'x' * len(blobs[name])
    write_tar(path, blobs.items())
    with pytest.raises(ValueError, match='digest'): gate().verify(path, REVISION, VERSION)

@pytest.mark.parametrize('case', ['missing', 'size', 'duplicate', 'wrong-reference', 'no-attestation', 'too-many', 'unsafe', 'duplicate-json', 'wrong-media'])
def test_rejects_incomplete_ambiguous_or_unbounded_graph(tmp_path, case):
    def change(blobs, index):
        if case == 'missing': blobs.pop('blobs/sha256/' + index['manifests'][0]['digest'][7:])
        elif case == 'size': index['manifests'][0]['size'] = 8 * 1024 ** 3
        elif case == 'duplicate': index['manifests'].append(index['manifests'][0])
        elif case == 'wrong-reference': index['manifests'][1]['annotations']['vnd.docker.reference.digest'] = 'sha256:' + '0' * 64
        elif case == 'no-attestation': index['manifests'].pop()
        elif case == 'too-many': index['manifests'] *= 2000
        elif case == 'wrong-media': index['manifests'][0]['mediaType'] = CONFIG
    path, _, _, _, _, blobs = fixture(tmp_path, change=change)
    if case == 'unsafe': blobs['../escape'] = b'bad'
    elif case == 'duplicate-json': blobs['index.json'] = b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}'
    write_tar(path, blobs.items())
    with pytest.raises(ValueError): gate().verify(path, REVISION, VERSION)

@pytest.mark.parametrize('kwargs', [{'revision': 'b' * 40}, {'platform': 'arm64'}])
def test_rejects_wrong_source_or_platform(tmp_path, kwargs):
    path, *_ = fixture(tmp_path, **kwargs)
    with pytest.raises(ValueError): gate().verify(path, REVISION, VERSION)

def test_rejects_duplicate_archive_member_and_symlink(tmp_path):
    path, *_, blobs = fixture(tmp_path)
    write_tar(path, [*blobs.items(), ('index.json', blobs['index.json'])])
    with pytest.raises(ValueError): gate().verify(path, REVISION, VERSION)
    write_tar(path, blobs.items())
    with tarfile.open(path, 'a') as archive:
        entry = tarfile.TarInfo('evil')
        entry.type = tarfile.SYMTYPE
        entry.linkname = '/etc/passwd'
        archive.addfile(entry)
    with pytest.raises(ValueError): gate().verify(path, REVISION, VERSION)

def scan_report(candidate):
    return {'matches': [], 'source': {'type': 'image', 'target': {'imageID': candidate['config_digest'], 'manifestDigest': candidate['manifest_digest'], 'layers': [{'digest': value} for value in candidate['diff_ids']]}},
        'descriptor': {'name': 'grype', 'version': 'test', 'db': {'status': {'valid': True}}}}

@pytest.mark.parametrize('case', ['success', 'exists', 'registry-mismatch', 'changed-candidate', 'bad-scan', 'wrong-scan', 'changed-smoke'])
def test_executable_publish_gate_uses_original_archive_and_full_readback(tmp_path, monkeypatch, case):
    path, _, _, config, _, blobs = fixture(tmp_path)
    module = gate()
    expected = module.verify(path, REVISION, VERSION)
    scan = scan_report(expected)
    if case == 'bad-scan': scan = {}
    if case == 'wrong-scan': scan['source']['target']['imageID'] = 'sha256:' + '0' * 64
    report = tmp_path / 'scan.json'
    report.write_bytes(encoded(scan))
    smoke = {'Id': config['digest'], 'RootFS': {'Layers': expected['diff_ids']}}
    if case == 'changed-smoke': smoke['RootFS']['Layers'] = ['sha256:' + '0' * 64]
    if case == 'changed-candidate':
        blobs['index.json'] += b' '
        write_tar(path, blobs.items())
    published = []
    def absent():
        if case == 'exists': raise ValueError('already published')
    def run(command, **kwargs):
        assert command[:3] == ['skopeo', 'copy', '--all']
        assert '--preserve-digests' in command
        if command[-1].startswith('docker://'):
            assert command[-2] == 'oci-archive:' + str(path)
            published.append(path.read_bytes())
        else:
            assert command[-2].startswith('docker://')
            dest = Path(command[-1].removeprefix('oci-archive:'))
            shutil.copyfile(path, dest)
            if case == 'registry-mismatch':
                other = tmp_path / 'other'
                other.mkdir()
                fixture(other, revision='b' * 40)
                shutil.copyfile(other / 'candidate.tar', dest)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(module.subprocess, 'run', run)
    args = (path, expected, report, smoke, 'ghcr.io/stepan-fair/ha-tunnel-server-amd64:0.4.3')
    if case == 'success':
        result = module.publish(*args, require_absent=absent)
        assert result['index_digest'] == expected['index_digest']
        assert published == [path.read_bytes()]
    else:
        with pytest.raises(ValueError): module.publish(*args, require_absent=absent)
        if case != 'registry-mismatch': assert not published

@pytest.mark.parametrize('artifact', [False, True])
@pytest.mark.parametrize('wrap', [False, True])
def test_roundtrip_accepts_repacked_layout_but_not_changed_graph(tmp_path, monkeypatch, wrap, artifact):
    path, _, _, config, _, _ = fixture(tmp_path, wrap=wrap, artifact=artifact)
    other = tmp_path / 'readback'
    other.mkdir()
    repacked, *_ = fixture(other, wrap=not wrap, artifact=artifact)
    module = gate()
    expected = module.verify(path, REVISION, VERSION)
    def run(command, **kwargs):
        if command[-1].startswith('oci-archive:'):
            shutil.copyfile(repacked, command[-1].removeprefix('oci-archive:'))
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(module.subprocess, 'run', run)
    module.copy_and_verify(path, expected, 'localhost:5443/ha-tunnel-candidate:0.4.3')

@pytest.mark.parametrize('data', [b'[' * 80 + b']' * 80, b'{"x":NaN}', b'{"x":1,"x":2}'])
def test_json_parser_rejects_depth_nonfinite_and_duplicates(data):
    with pytest.raises(ValueError): gate().read_json(data)

def test_oversize_extended_tar_header_is_rejected_before_read(tmp_path):
    path = tmp_path / 'bad.tar'
    entry = tarfile.TarInfo('pax')
    entry.type = tarfile.XHDTYPE
    entry.size = 100 * 1024**2
    path.write_bytes(entry.tobuf() + b'\0' * 1024)
    with pytest.raises(ValueError, match='header limit'): gate().verify(path, REVISION, VERSION)

def test_scan_with_failed_database_is_not_accepted(tmp_path):
    path, _, _, config, _, _ = fixture(tmp_path)
    module = gate()
    expected = module.verify(path, REVISION, VERSION)
    scan = scan_report(expected)
    scan['descriptor']['db'] = {'error': 'database unavailable'}
    report = tmp_path / 'scan.json'
    report.write_bytes(encoded(scan))
    with pytest.raises(ValueError):
        module.validate_gate(path, expected, report, {'Id': config['digest'], 'RootFS': {'Layers': expected['diff_ids']}})

@pytest.mark.parametrize('case', ['invalid-db', 'missing-db', 'uncompressed-limit'])
def test_rejects_unusable_scan_metadata_and_excessive_json(tmp_path, case):
    path, _, _, config, _, _ = fixture(tmp_path)
    module = gate()
    candidate = module.verify(path, REVISION, VERSION)
    scan = scan_report(candidate)
    if case == 'invalid-db': scan['descriptor']['db'] = {'status': {'valid': False}}
    elif case == 'missing-db': scan['descriptor'].pop('db', None)
    else:
        with pytest.raises(ValueError, match='node limit'):
            module.read_json(b'[' + b'[],' * 500001 + b'[]]')
        return
    report = tmp_path / 'scan.json'
    report.write_bytes(encoded(scan))
    with pytest.raises(ValueError):
        module.validate_gate(path, candidate, report, {'Id': config['digest'], 'RootFS': {'Layers': candidate['diff_ids']}})

def test_rehearsal_refuses_existing_tls_registry_tag(tmp_path, monkeypatch):
    import urllib.request
    path, _, _, config, _, _ = fixture(tmp_path)
    module = gate()
    candidate = module.verify(path, REVISION, VERSION)
    scan = tmp_path / 'scan.json'
    scan.write_bytes(encoded(scan_report(candidate)))
    called = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    monkeypatch.setattr(urllib.request, 'urlopen', lambda *args, **kwargs: Response())
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs: called.append(args))
    with pytest.raises(ValueError, match='already published'):
        module.rehearsal(path, candidate, scan, {'Id': config['digest'], 'RootFS': {'Layers': candidate['diff_ids']}},
                         'localhost:5443/ha-tunnel-candidate:0.4.3', None)
    assert not called


def test_scan_with_same_config_but_different_layer_graph_is_rejected(tmp_path):
    path, *_ = fixture(tmp_path)
    module = gate()
    expected = module.verify(path, REVISION, VERSION)
    scan = scan_report(expected)
    scan['source']['target']['layers'][0]['digest'] = 'sha256:' + '0' * 64
    report = tmp_path / 'scan.json'
    report.write_bytes(encoded(scan))
    with pytest.raises(ValueError):
        module.validate_gate(path, expected, report,
            {'Id': expected['config_digest'], 'RootFS': {'Layers': expected['diff_ids']}})


@pytest.mark.parametrize('changed', [None, 'config', 'manifest', 'diff_id'])
def test_gzip_scan_contract_uses_uncompressed_diff_ids(tmp_path, changed):
    path, _, _, _, layer, blobs = fixture(tmp_path)
    module = gate()
    expected = module.verify(path, REVISION, VERSION)
    compressed = blobs['blobs/sha256/' + layer['digest'][7:]]
    uncompressed_id = 'sha256:' + hashlib.sha256(gzip.decompress(compressed)).hexdigest()
    assert uncompressed_id != layer['digest']
    report = scan_report(expected)
    target = report['source']['target']
    target['layers'] = [{'digest': uncompressed_id, 'size': len(gzip.decompress(compressed)), 'mediaType': LAYER}]
    if changed == 'config': target['imageID'] = 'sha256:' + '0' * 64
    elif changed == 'manifest': target['manifestDigest'] = 'sha256:' + '0' * 64
    elif changed == 'diff_id': target['layers'][0]['digest'] = 'sha256:' + '0' * 64
    scan = tmp_path / 'scan.json'
    scan.write_bytes(encoded(report))
    inspected = {'Id': expected['config_digest'], 'RootFS': {'Layers': expected['diff_ids']}}
    if changed:
        with pytest.raises(ValueError): module.validate_gate(path, expected, scan, inspected)
    else:
        assert module.validate_gate(path, expected, scan, inspected)['layers'] == [layer['digest']]


@pytest.mark.parametrize('version', ['0.0', '0.1', '1.0'])
@pytest.mark.parametrize('global_header', [False, True])
def test_sparse_pax_rejected_before_map_handler_or_body_read(version, global_header, monkeypatch):
    module = gate()
    fields = {
        '0.0': {'GNU.sparse.size': '20000', 'GNU.sparse.offset': '0', 'GNU.sparse.numbytes': '1'},
        '0.1': {'GNU.sparse.map': '0,1', 'GNU.sparse.realsize': '20000'},
        '1.0': {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0', 'GNU.sparse.realsize': '20000'},
    }[version]
    pax = tarfile.TarInfo.create_pax_global_header(fields)
    if not global_header:
        # Recalculate checksum for the local extended-header type.
        header = tarfile.TarInfo.frombuf(pax[:512], 'utf-8', 'strict')
        header.type = tarfile.XHDTYPE
        pax = header.tobuf() + pax[512:]
    payload = b'20000\n' + b'0\n1\n' * 20000
    entry = tarfile.TarInfo('blobs/sha256/' + '0' * 64)
    entry.size = len(payload)
    body_start = len(pax) + 512
    class Reader(io.BytesIO):
        body_reads = 0
        def read(self, size=-1):
            if self.tell() >= body_start and size: self.body_reads += 1
            return super().read(size)
    reader = Reader(pax + entry.tobuf() + payload + b'\0' * 10240)
    handlers = []
    for name in ('_proc_gnusparse_00', '_proc_gnusparse_01', '_proc_gnusparse_10'):
        original = getattr(tarfile.TarInfo, name)
        def watched(self, *args, _original=original, _name=name):
            handlers.append(_name)
            return _original(self, *args)
        monkeypatch.setattr(tarfile.TarInfo, name, watched)
    with pytest.raises(ValueError, match='Sparse'):
        with tarfile.open(fileobj=reader, mode='r:', tarinfo=module.BoundedTarInfo):
            pass
    assert handlers == []
    assert reader.body_reads == 0


@pytest.mark.parametrize('case', [
    'subject-digest', 'subject-size', 'subject-media', 'subject-null', 'subject-absent',
    'subject-inline', 'subject-external', 'subject-extra', 'artifact-unknown', 'artifact-absent',
    'config-data', 'config-no-data', 'config-digest', 'config-size', 'config-media',
    'config-external', 'config-extra', 'config-missing-blob', 'config-replaced-blob',
    'statement-subject', 'statement-empty', 'statement-absent', 'statement-null', 'extra-blob',
])
def test_artifact_attestation_rejects_unbound_or_noncanonical_graph(tmp_path, case):
    def change(blobs, index):
        descriptor = index['manifests'][1]
        old = 'blobs/sha256/' + descriptor['digest'][7:]
        document = json.loads(blobs.pop(old))
        subject, config = document['subject'], document['config']
        if case == 'subject-digest': subject['digest'] = 'sha256:' + '0' * 64
        elif case == 'subject-size': subject['size'] += 1
        elif case == 'subject-media': subject['mediaType'] = INDEX
        elif case == 'subject-null': document['subject'] = None
        elif case == 'subject-absent': document.pop('subject')
        elif case == 'subject-inline': subject['data'] = 'e30='
        elif case == 'subject-external': subject['urls'] = ['https://example.invalid/blob']
        elif case == 'subject-extra': subject['artifactType'] = ARTIFACT
        elif case == 'artifact-unknown': document['artifactType'] = 'unknown'
        elif case == 'artifact-absent': document.pop('artifactType')
        elif case == 'config-data': config['data'] = 'bnVsbA=='
        elif case == 'config-no-data': config.pop('data')
        elif case == 'config-digest': config['digest'] = 'sha256:' + '0' * 64
        elif case == 'config-size': config['size'] = 3
        elif case == 'config-media': config['mediaType'] = CONFIG
        elif case == 'config-external': config['urls'] = ['https://example.invalid/blob']
        elif case == 'config-extra': config['artifactType'] = ARTIFACT
        elif case == 'config-missing-blob': blobs.pop('blobs/sha256/' + config['digest'][7:])
        elif case == 'config-replaced-blob': blobs['blobs/sha256/' + config['digest'][7:]] = b'[]'
        elif case == 'extra-blob': blobs['blobs/sha256/' + hashlib.sha256(b'unbound').hexdigest()] = b'unbound'
        elif case.startswith('statement-'):
            layer = document['layers'][0]
            statement = json.loads(blobs.pop('blobs/sha256/' + layer['digest'][7:]))
            if case == 'statement-subject': statement['subject'][0]['digest']['sha256'] = '0' * 64
            elif case == 'statement-empty': statement['subject'] = []
            elif case == 'statement-absent': statement.pop('subject')
            elif case == 'statement-null': statement['subject'] = None
            data = encoded(statement)
            layer.update(digest='sha256:' + hashlib.sha256(data).hexdigest(), size=len(data))
            blobs['blobs/sha256/' + layer['digest'][7:]] = data
        data = encoded(document)
        descriptor.update(digest='sha256:' + hashlib.sha256(data).hexdigest(), size=len(data))
        blobs['blobs/sha256/' + descriptor['digest'][7:]] = data
    path, *_ = fixture(tmp_path, artifact=True, change=change)
    with pytest.raises(ValueError):
        gate().verify(path, REVISION, VERSION)


@pytest.mark.parametrize('location', ['envelope', 'index', 'runnable', 'legacy-attestation'])
@pytest.mark.parametrize('field', ['subject', 'artifactType'])
def test_rejects_subject_or_artifact_type_outside_supported_artifact(tmp_path, location, field):
    def change(blobs, index):
        value = None if field == 'subject' else ARTIFACT
        if location == 'index':
            index[field] = value
        elif location in ('runnable', 'legacy-attestation'):
            descriptor = index['manifests'][0 if location == 'runnable' else 1]
            document = json.loads(blobs.pop('blobs/sha256/' + descriptor['digest'][7:]))
            document[field] = value
            data = encoded(document)
            descriptor.update(digest='sha256:' + hashlib.sha256(data).hexdigest(), size=len(data))
            blobs['blobs/sha256/' + descriptor['digest'][7:]] = data
    path, *_, blobs = fixture(tmp_path, change=change)
    if location == 'envelope':
        index = json.loads(blobs['index.json'])
        index[field] = None if field == 'subject' else ARTIFACT
        blobs['index.json'] = encoded(index)
        write_tar(path, blobs.items())
    if location == 'envelope':
        error = 'Unexpected layout index artifact'
    elif location == 'legacy-attestation':
        error = 'Unexpected attestation artifact type' if field == 'subject' else 'Artifact subject mismatch'
    else:
        error = 'Unexpected graph subject' if field == 'subject' else 'Unexpected graph artifact type'
    with pytest.raises(ValueError, match=error):
        gate().verify(path, REVISION, VERSION)
