"""Verify and publish the one scanned OCI candidate, including attestations.

The OCI layout's index.json may be an envelope around the actual image index.
Only the original archive is publishable. Docker's runnable copy is for smoke
tests; its config digest and uncompressed layer identities must match.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
ATTEST = 'application/vnd.in-toto+json'
LAYERS = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
          'application/vnd.oci.image.layer.v1.tar+zstd'}
MAX_ARCHIVE = 8 * 1024**3
MAX_BLOB = 2 * 1024**3
MAX_JSON = 32 * 1024**2
MAX_ENTRIES = 4096
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def hash_stream(stream):
    result = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        result.update(chunk)
    return 'sha256:' + result.hexdigest()


def read_json(data):
    require(len(data) <= MAX_JSON, 'JSON size limit')
    # Bound nesting before the parser allocates objects or recurses.
    depth = nodes = 0
    quoted = escaped = False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            nodes += 1
            require(nodes <= 500000, 'JSON node limit')
            depth += 1
            require(depth <= 64, 'JSON depth limit')
        elif char == 44:
            nodes += 1
            require(nodes <= 500000, 'JSON node limit')
        elif char in (93, 125):
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('Invalid JSON number')
    try:
        result = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Invalid JSON') from error
    pending = [result]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        require(count <= 500000, 'JSON node limit')
        if isinstance(node, dict):
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return result


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_pax(self, archive):
        # The stdlib allocates sparse maps inside _proc_pax, before returning
        # the entry. Inspect only the bounded extended-header payload first.
        # Reject every GNU sparse key/version, including global/Solaris PAX.
        require(0 <= self.size <= 65536, 'Archive extended header limit')
        position = archive.fileobj.tell()
        header = archive.fileobj.read(self._block(self.size))
        require(b'GNU.sparse.' not in header and not any(
            key.startswith('GNU.sparse.') for key in archive.pax_headers),
            'Sparse PAX archive entry')
        archive.fileobj.seek(position)
        return super()._proc_pax(archive)

    def _proc_member(self, archive):
        # tarfile otherwise reads extended headers before the caller sees them.
        archive._candidate_headers = getattr(archive, '_candidate_headers', 0) + 1
        require(archive._candidate_headers <= MAX_ENTRIES, 'Archive header count limit')
        require(0 <= self.size <= MAX_BLOB, 'Archive member size limit')
        if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            require(self.size <= 65536, 'Archive extended header limit')
            archive._candidate_extensions = getattr(archive, '_candidate_extensions', 0) + 1
            require(archive._candidate_extensions <= 8, 'Archive extended header chain limit')
        require(self.type != tarfile.GNUTYPE_SPARSE, 'Sparse archive entry')
        try:
            return super()._proc_member(archive)
        finally:
            if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                archive._candidate_extensions -= 1


class Archive:
    def __init__(self, path):
        require(Path(path).stat().st_size <= MAX_ARCHIVE, 'Archive size limit')
        self.tar = tarfile.open(path, 'r:', tarinfo=BoundedTarInfo)
        self.members = {}
        self.verified = {}
        self.json_bytes = 0
        try:
            for entry in self.tar:
                require(len(self.members) < MAX_ENTRIES, 'Archive entry limit')
                name = entry.name
                require(name not in self.members, 'Duplicate archive member')
                require(entry.isfile() or entry.isdir(), 'Unsafe archive entry')
                require(not entry.sparse, 'Sparse archive entry')
                require(0 <= entry.size <= MAX_BLOB, 'Archive member size limit')
                if entry.isdir():
                    require(name in ('blobs', 'blobs/sha256'), 'Unsafe archive directory')
                else:
                    require(name in ('index.json', 'oci-layout') or
                            re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', name), 'Unsafe archive path')
                self.members[name] = entry
        except BaseException:
            self.tar.close()
            raise

    def close(self):
        self.tar.close()

    def raw(self, name):
        entry = self.members.get(name)
        require(entry is not None and entry.isfile(), 'Missing blob or layout')
        require(entry.size <= MAX_JSON, 'JSON size limit')
        self.json_bytes += entry.size
        require(self.json_bytes <= 64 * 1024**2, 'Graph metadata size limit')
        with self.tar.extractfile(entry) as stream:
            return stream.read(MAX_JSON + 1)

    def descriptor(self, descriptor, allowed, *, parse=False):
        require(isinstance(descriptor, dict), 'Invalid descriptor')
        media, identity, size = (descriptor.get(key) for key in ('mediaType', 'digest', 'size'))
        require(media in allowed and isinstance(identity, str) and DIGEST.fullmatch(identity), 'Invalid descriptor media/digest')
        require(type(size) is int and 0 <= size <= (MAX_JSON if parse else MAX_BLOB), 'Descriptor size limit')
        require(not any(key in descriptor for key in ('urls', 'data', 'artifactType')), 'External or inline descriptor')
        previous = self.verified.get(identity)
        require(previous is None or previous == (media, size), 'Conflicting descriptor')
        name = 'blobs/sha256/' + identity[7:]
        entry = self.members.get(name)
        require(entry is not None and entry.isfile(), 'Missing blob')
        require(entry.size == size, 'Descriptor size mismatch')
        if previous is None:
            with self.tar.extractfile(entry) as stream:
                require(hash_stream(stream) == identity, 'Blob digest mismatch')
            self.verified[identity] = (media, size)
        if parse:
            return read_json(self.raw(name))

    def document(self, descriptor, media):
        value = self.descriptor(descriptor, {media}, parse=True)
        require(isinstance(value, dict) and value.get('schemaVersion') == 2 and value.get('mediaType') == media,
                'Invalid graph media/schema')
        require('subject' not in value, 'Unexpected graph subject')
        return value


def verify(path, revision, version, platform='linux/amd64'):
    require(re.fullmatch(r'[0-9a-f]{40}', revision) is not None, 'Invalid source revision')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) is not None, 'Invalid version')
    require(platform == 'linux/amd64', 'Unsupported platform')
    archive = Archive(path)
    try:
        layout = read_json(archive.raw('oci-layout'))
        require(layout == {'imageLayoutVersion': '1.0.0'}, 'Invalid OCI layout')
        envelope = archive.raw('index.json')
        index = read_json(envelope)
        require(isinstance(index, dict) and index.get('schemaVersion') == 2 and
                index.get('mediaType', INDEX) == INDEX, 'Invalid layout index')
        manifests = index.get('manifests')
        require(isinstance(manifests, list) and 1 <= len(manifests) <= 16, 'Manifest count limit')
        index_digest = digest(envelope)
        if len(manifests) == 1 and manifests[0].get('mediaType') == INDEX:
            index = archive.document(manifests[0], INDEX)
            index_digest = manifests[0]['digest']
            manifests_size = manifests[0]['size']
            manifests = index.get('manifests')
        require(isinstance(manifests, list) and 2 <= len(manifests) <= 16, 'Image index requires runnable and attestations')
        require(all(isinstance(item, dict) for item in manifests), 'Invalid manifest descriptor')
        require(len({item.get('digest') for item in manifests}) == len(manifests), 'Duplicate manifest descriptor')
        runnable = [item for item in manifests if item.get('platform') == {'os': 'linux', 'architecture': 'amd64'}]
        require(len(runnable) == 1, 'Wrong or ambiguous platform')
        selected = runnable[0]
        manifest = archive.document(selected, MANIFEST)
        config_descriptor = manifest.get('config')
        config = archive.descriptor(config_descriptor, {CONFIG}, parse=True)
        require(isinstance(config, dict) and config.get('os') == 'linux' and config.get('architecture') == 'amd64',
                'Config platform mismatch')
        labels = config.get('config', {}).get('Labels', {})
        require(labels.get('org.opencontainers.image.revision') == revision, 'Source revision mismatch')
        require(labels.get('org.opencontainers.image.version') == version, 'Version mismatch')
        layers = manifest.get('layers')
        require(isinstance(layers, list) and 1 <= len(layers) <= 128, 'Layer count limit')
        for layer in layers:
            archive.descriptor(layer, LAYERS)
        rootfs = config.get('rootfs', {})
        diff_ids = rootfs.get('diff_ids')
        require(rootfs.get('type') == 'layers' and isinstance(diff_ids, list) and len(diff_ids) == len(layers)
                and all(isinstance(value, str) and DIGEST.fullmatch(value) for value in diff_ids), 'Invalid rootfs')
        attestations, kinds = [], set()
        for item in manifests:
            if item is selected:
                continue
            require(item.get('platform') == {'os': 'unknown', 'architecture': 'unknown'}, 'Unexpected platform')
            annotations = item.get('annotations', {})
            require(annotations.get('vnd.docker.reference.type') == 'attestation-manifest' and
                    annotations.get('vnd.docker.reference.digest') == selected['digest'], 'Attestation reference mismatch')
            attestation = archive.document(item, MANIFEST)
            att_config = archive.descriptor(attestation.get('config'), {CONFIG}, parse=True)
            require(isinstance(att_config, dict) and att_config.get('architecture') == 'unknown' and
                    att_config.get('os') == 'unknown', 'Invalid attestation config')
            att_layers = attestation.get('layers')
            require(isinstance(att_layers, list) and 1 <= len(att_layers) <= 16, 'Attestation layer limit')
            for layer in att_layers:
                statement = archive.descriptor(layer, {ATTEST}, parse=True)
                require(isinstance(statement, dict), 'Invalid attestation statement')
                kind = statement.get('predicateType')
                require(kind in ('https://slsa.dev/provenance/v0.2', 'https://slsa.dev/provenance/v1', 'https://spdx.dev/Document'),
                        'Unexpected attestation predicate')
                require(statement.get('_type') in ('https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1'),
                        'Invalid attestation type')
                require(layer.get('annotations', {}).get('in-toto.io/predicate-type') == kind, 'Predicate annotation mismatch')
                subjects = statement.get('subject')
                require(isinstance(subjects, list) and 1 <= len(subjects) <= 16 and all(
                    isinstance(subject, dict) and subject.get('digest') == {'sha256': selected['digest'][7:]}
                    for subject in subjects), 'Attestation subject mismatch')
                require(isinstance(statement.get('predicate'), dict) and statement['predicate'], 'Missing predicate')
                kinds.add('provenance' if 'slsa.dev' in kind else 'sbom')
            attestations.append(item['digest'])
        require(kinds == {'provenance', 'sbom'}, 'Missing SBOM or provenance')
        referenced = {'blobs/sha256/' + key[7:] for key in archive.verified}
        require({name for name, entry in archive.members.items() if entry.isfile()} ==
                referenced | {'index.json', 'oci-layout'}, 'Unreferenced archive blob')
        archive.verified[index_digest] = (INDEX, len(envelope) if index_digest == digest(envelope) else manifests_size)
        with open(path, 'rb') as stream:
            archive_digest = hash_stream(stream)
        return {'schema': 1, 'revision': revision, 'version': version, 'platform': platform,
                'archive_digest': archive_digest, 'layout_digest': digest(envelope), 'index_digest': index_digest,
                'manifest_digest': selected['digest'], 'config_digest': config_descriptor['digest'],
                'layers': [layer['digest'] for layer in layers], 'diff_ids': diff_ids,
                'attestations': attestations, 'descriptors': {key: list(value) for key, value in sorted(archive.verified.items())}}
    except (KeyError, TypeError, AttributeError, tarfile.TarError) as error:
        raise ValueError('Malformed OCI graph') from error
    finally:
        archive.close()


def read_json_file(path):
    with open(path, 'rb') as stream:
        return read_json(stream.read(MAX_JSON + 1))


def verify_smoke(candidate, inspected):
    require(isinstance(inspected, dict) and inspected.get('Id') == candidate['config_digest'] and
            inspected.get('RootFS', {}).get('Layers') == candidate['diff_ids'], 'Smoke config/layers mismatch')


def validate_gate(path, expected, scan, inspected):
    actual = verify(path, expected['revision'], expected['version'], expected['platform'])
    require(actual == expected, 'Candidate changed since verification')
    if __package__:
        from tools.check_image_scan import check
    else:
        from check_image_scan import check
    report = read_json_file(scan)
    check(report)
    database = report.get('descriptor', {}).get('db', {})
    require(not database.get('error') and database.get('status', {}).get('valid') is True, 'Scan database error or invalid status')
    require(report.get('descriptor', {}).get('name') == 'grype' and report.get('source', {}).get('type') == 'image'
            and report['source'].get('target', {}).get('imageID') == actual['config_digest'], 'Scan image identity mismatch')
    # Grype/Syft layer metadata uses uncompressed diff IDs. The exact
    # compressed blobs remain bound by the verified manifest digest/graph.
    target = report['source']['target']
    require(target.get('manifestDigest') == actual['manifest_digest'] and
            isinstance(target.get('layers'), list) and
            [layer.get('digest') for layer in target['layers']] == actual['diff_ids'],
            'Scan manifest/layers mismatch')
    verify_smoke(actual, inspected)
    return actual


def publish(path, expected, scan, inspected, target, *, require_absent):
    actual = validate_gate(path, expected, scan, inspected)
    require(target == 'ghcr.io/stepan-fair/ha-tunnel-server-amd64:' + actual['version'] or
            target == 'ghcr.io/stepan-fair/ha-tunnel-client-amd64:' + actual['version'], 'Invalid publish target/version')
    require_absent()
    return copy_and_verify(path, actual, target)


def copy_and_verify(path, actual, target):
    subprocess.run(['skopeo', 'copy', '--all', '--preserve-digests', 'oci-archive:' + str(path),
                    'docker://' + target], check=True, timeout=900)
    with tempfile.TemporaryDirectory(prefix='ha-tunnel-registry-') as directory:
        readback = Path(directory) / 'readback.tar'
        subprocess.run(['skopeo', 'copy', '--all', '--preserve-digests', 'docker://' + target,
                        'oci-archive:' + str(readback)], check=True, timeout=900)
        registered = verify(readback, actual['revision'], actual['version'], actual['platform'])
        # Registry/Skopeo may rewrite the layout envelope/tar headers, never the image graph.
        for key in ('index_digest', 'manifest_digest', 'config_digest', 'layers', 'diff_ids', 'attestations', 'descriptors'):
            require(registered[key] == actual[key], 'Registry digest graph mismatch')
    return actual


def rehearsal(path, expected, scan, inspected, target, ca):
    """Exercise actual TLS registry copy/readback on an isolated runner only."""
    import ssl
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen
    actual = validate_gate(path, expected, scan, inspected)
    require(target == 'localhost:5443/ha-tunnel-candidate:' + actual['version'], 'Invalid rehearsal target')
    request = Request('https://localhost:5443/v2/ha-tunnel-candidate/manifests/' + actual['version'],
                      headers={'Accept': INDEX})
    try:
        with urlopen(request, context=ssl.create_default_context(cafile=ca), timeout=15):
            raise ValueError('Version already published')
    except HTTPError as error:
        require(error.code == 404, 'Registry did not confirm absence')
        body = read_json(error.read(65537))
        errors = body.get('errors')
        require(isinstance(errors, list) and errors and all(
            item.get('code') in ('MANIFEST_UNKNOWN', 'NAME_UNKNOWN') for item in errors),
            'Registry did not confirm absence')
    return copy_and_verify(path, actual, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('verify', 'smoke', 'gate', 'publish', 'rehearse'))
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--scan', type=Path)
    parser.add_argument('--inspection', type=Path)
    parser.add_argument('--target')
    parser.add_argument('--ca')
    args = parser.parse_args()
    if args.command == 'verify':
        result = verify(args.archive, args.revision, args.version)
        args.record.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    else:
        expected = read_json_file(args.record)
        require(expected['revision'] == args.revision and expected['version'] == args.version, 'Gate metadata mismatch')
        inspected = read_json_file(args.inspection)
        if isinstance(inspected, list) and len(inspected) == 1:
            inspected = inspected[0]
        if args.command == 'smoke':
            actual = verify(args.archive, args.revision, args.version)
            require(actual == expected, 'Candidate changed since verification')
            verify_smoke(actual, inspected)
        elif args.command == 'gate':
            validate_gate(args.archive, expected, args.scan, inspected)
        elif args.command == 'rehearse':
            rehearsal(args.archive, expected, args.scan, inspected, args.target, args.ca)
        else:
            require(os.environ.get('IMAGE', '') + ':' + os.environ.get('VERSION', '') == args.target, 'Registry guard target mismatch')
            if __package__:
                from tools.release_templates.guard_image import main as guard
            else:
                from release_templates.guard_image import main as guard
            publish(args.archive, expected, args.scan, inspected, args.target, require_absent=guard)
    print('OCI candidate verification passed')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
