"""Verify staged public OCI bytes without importing or running an image."""

import hashlib
import json
from pathlib import Path
import re
import tarfile


def verify_archive(path, expected_digest, *, expected_sha256=None):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest):
        raise ValueError('Public asset identity denied')
    size = path.stat().st_size
    if not 0 < size <= 2 << 30:
        raise ValueError('Public asset archive bounds denied')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for raw in iter(lambda: stream.read(1 << 20), b''):
            digest.update(raw)
    archive_sha = digest.hexdigest()
    if expected_sha256 is not None and archive_sha != expected_sha256:
        raise ValueError('Public asset archive checksum mismatch')
    with tarfile.open(path, 'r:') as archive:
        members = archive.getmembers()
        if len(members) > 4096 or len({m.name for m in members}) != len(members):
            raise ValueError('Public archive duplicate or excessive entries')
        if any(not (m.isfile() or m.isdir()) or m.name.startswith('/') or '..' in Path(m.name).parts for m in members):
            raise ValueError('Public archive unsafe entry')
        lookup = {m.name: m for m in members if m.isfile()}
        if any(name not in ('index.json', 'manifest.json', 'oci-layout')
            and not re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', name) for name in lookup):
            raise ValueError('Public OCI archive contains an unexpected file')

        def blob(descriptor, maximum=16 << 20):
            reference = descriptor.get('digest')
            if not isinstance(reference, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', reference):
                raise ValueError('Public descriptor digest invalid')
            item = lookup.get('blobs/sha256/' + reference.split(':')[1])
            if item is None or not 0 < item.size <= maximum or descriptor.get('size', item.size) != item.size:
                raise ValueError('Public descriptor size or content absent')
            stream = archive.extractfile(item)
            result = stream.read(maximum + 1)
            if 'sha256:' + hashlib.sha256(result).hexdigest() != reference:
                raise ValueError('Public immutable blob checksum mismatch')
            return result

        def document(descriptor):
            value = json.loads(blob(descriptor))
            if not isinstance(value, dict):
                raise ValueError('Public manifest document invalid')
            return value

        layout = lookup.get('oci-layout')
        index = lookup.get('index.json')
        if layout is None or index is None or max(layout.size, index.size) > 1 << 20:
            raise ValueError('Public OCI layout absent')
        if json.load(archive.extractfile(layout)) != {'imageLayoutVersion': '1.0.0'}:
            raise ValueError('Public OCI layout version invalid')
        outer = json.load(archive.extractfile(index))
        descriptors = outer.get('manifests', [])
        if len(descriptors) != 1 or descriptors[0].get('digest') != expected_digest:
            raise ValueError('Public OCI root descriptor mismatch')
        node = document({'digest': expected_digest})
        selected_digest = expected_digest
        for _ in range(4):
            if 'manifests' not in node:
                break
            choices = [v for v in node['manifests'] if v.get('platform', {}).get('os') == 'linux'
                and v.get('platform', {}).get('architecture') == 'amd64']
            if len(choices) != 1:
                raise ValueError('Public linux amd64 manifest is not unique')
            selected_digest = choices[0]['digest']
            node = document(choices[0])
        if node.get('schemaVersion') != 2 or 'manifests' in node or not isinstance(node.get('layers'), list):
            raise ValueError('Public image manifest invalid')
        config = document(node['config'])
        if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
            raise ValueError('Public image platform mismatch')
        legacy = lookup.get('manifest.json')
        if legacy is not None:
            if legacy.size > 1 << 20:
                raise ValueError('Public compatibility manifest exceeds bounds')
            records = json.load(archive.extractfile(legacy))
            expected_layers = ['blobs/sha256/' + v['digest'].split(':')[1] for v in node['layers']]
            if not isinstance(records, list) or len(records) != 1 or records[0].get('Config') != 'blobs/sha256/' + node['config']['digest'].split(':')[1] or records[0].get('Layers') != expected_layers:
                raise ValueError('Public compatibility manifest differs from verified image')
        for descriptor in node['layers']:
            reference = descriptor.get('digest', '')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', reference):
                raise ValueError('Public layer digest invalid')
            item = lookup.get('blobs/sha256/' + reference.split(':')[1])
            if item is None or item.size != descriptor.get('size') or not 0 < item.size <= 1 << 30:
                raise ValueError('Public layer bounds or content absent')
            checksum = hashlib.sha256()
            with archive.extractfile(item) as stream:
                for raw in iter(lambda: stream.read(1 << 20), b''):
                    checksum.update(raw)
            if 'sha256:' + checksum.hexdigest() != reference:
                raise ValueError('Public layer checksum mismatch')
    return {'archiveBytes': size, 'archiveSHA256': archive_sha, 'rootDigest': expected_digest,
        'linuxAMD64ManifestDigest': selected_digest, 'configDigest': node['config']['digest'],
        'verifiedLayers': len(node['layers']), 'imageImportedOrExecuted': False, 'production': False}
