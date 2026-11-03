import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from public_assets import verify_archive


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class AssetGuards(unittest.TestCase):
    def archive(self, root, *, architecture='amd64', tamper_layer=False, duplicate=False, extra=False, other_root=False, wrong_legacy=False):
        blobs = {}
        def add(value):
            content = value if isinstance(value, bytes) else raw(value)
            digest = 'sha256:' + hashlib.sha256(content).hexdigest()
            blobs['blobs/sha256/' + digest.split(':')[1]] = content
            return {'digest': digest, 'size': len(content)}
        config = add({'os': 'linux', 'architecture': architecture})
        layer = add(b'public-test-layer')
        descriptor = add({'schemaVersion': 2, 'config': config, 'layers': [layer]})
        blobs['oci-layout'] = raw({'imageLayoutVersion': '1.0.0'})
        blobs['index.json'] = raw({'schemaVersion': 2, 'manifests': [descriptor]})
        if other_root: blobs['index.json'] = raw({'schemaVersion': 2, 'manifests': [descriptor, descriptor]})
        if wrong_legacy: blobs['manifest.json'] = raw([{'Config': 'other', 'Layers': []}])
        if tamper_layer: blobs['blobs/sha256/' + layer['digest'].split(':')[1]] = b'wrong-layer-bytes'
        if extra: blobs['unreviewed'] = b'extra'
        path = root / 'asset.tar'
        with tarfile.open(path, 'w') as archive:
            for name, value in blobs.items():
                info = tarfile.TarInfo(name); info.size = len(value); archive.addfile(info, io.BytesIO(value))
            if duplicate:
                info = tarfile.TarInfo('index.json'); info.size = len(blobs['index.json']); archive.addfile(info, io.BytesIO(blobs['index.json']))
        return path, descriptor['digest']

    def test_all_blob_checksums_and_platform(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root))
            self.assertEqual(verify_archive(path, digest)['verifiedLayers'], 1)
    def test_root_digest_not_substituted(self):
        with tempfile.TemporaryDirectory() as root:
            path, _ = self.archive(Path(root))
            with self.assertRaises(ValueError): verify_archive(path, 'sha256:'+'f'*64)
    def test_layer_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root), tamper_layer=True)
            with self.assertRaises(ValueError): verify_archive(path, digest)
    def test_duplicate_member_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root), duplicate=True)
            with self.assertRaises(ValueError): verify_archive(path, digest)
    def test_wrong_platform_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root), architecture='arm64')
            with self.assertRaises(ValueError): verify_archive(path, digest)
    def test_archive_raw_sha_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root))
            with self.assertRaises(ValueError): verify_archive(path, digest, expected_sha256='0'*64)
    def test_unreviewed_file_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root), extra=True)
            with self.assertRaises(ValueError): verify_archive(path, digest)
    def test_extra_root_import_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root), other_root=True)
            with self.assertRaises(ValueError): verify_archive(path, digest)
    def test_legacy_manifest_cannot_choose_other_image(self):
        with tempfile.TemporaryDirectory() as root:
            path, digest = self.archive(Path(root), wrong_legacy=True)
            with self.assertRaises(ValueError): verify_archive(path, digest)


if __name__ == '__main__': unittest.main()
