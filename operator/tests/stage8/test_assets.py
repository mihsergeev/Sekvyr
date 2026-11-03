"""Public artifact import guards; no actual Docker, network, sudo or node."""
import hashlib
from contextlib import contextmanager
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stage8 import assets, profiles
from stage8.test_archive_graph import fixture_archive, tar_bytes
from stage8.test_profiles import SYNTHETIC

TEST_IMAGE = "example.invalid/test-image@sha256:" + "e" * 64


@contextmanager
def root_file_metadata():
    """Only this test's temporary file reads see synthetic UID 0."""
    lstat, fstat = Path.lstat, os.fstat
    fields = ("st_dev", "st_ino", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns")

    def owned(info):
        # Windows temporary files expose synthesized world-writable mode bits.
        mode = info.st_mode & ~0o022 if os.name == "nt" else info.st_mode
        return SimpleNamespace(st_uid=0, st_mode=mode, **{field: getattr(info, field) for field in fields})

    with patch.object(Path, "lstat", lambda path: owned(lstat(path))), patch.object(os, "fstat", lambda fd: owned(fstat(fd))):
        yield


def static_elf():
    raw = bytearray(120)
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", raw, 18, 62)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<H", raw, 54, 56)
    struct.pack_into("<H", raw, 56, 1)
    return raw


def receipt(path, raw, root, amd):
    return {"path": str(path), "rootDigest": root["digest"], "archiveBytes": len(raw),
        "archiveSHA256": hashlib.sha256(raw).hexdigest(), "linuxAMD64ManifestDigest": amd["digest"]}


class ArtifactGuards(unittest.TestCase):
    def test_missing_or_floating_pins_never_construct_capability(self):
        with patch.object(profiles, "REVIEWED_ARTIFACTS", dict.fromkeys(SYNTHETIC)), patch.object(assets, "Capability") as cap:
            with self.assertRaises(RuntimeError): assets.run(None, profile="kind-1.37.0")
            cap.assert_not_called()
        with patch.object(profiles, "REVIEWED_ARTIFACTS", SYNTHETIC), patch.object(assets, "REVIEWED_BACKEND_TEST_IMAGE", "example.invalid/tests:latest"), patch.object(assets, "Capability") as cap:
            with self.assertRaises(RuntimeError): assets.run(None, profile="kind-1.34.11")
            cap.assert_not_called()

    def test_closed_new_refs_preserve_four_public_dependencies_without_mutating_legacy(self):
        original = dict(assets.legacy.REFERENCES)
        with patch.object(profiles, "REVIEWED_ARTIFACTS", SYNTHETIC), patch.object(assets, "REVIEWED_BACKEND_TEST_IMAGE", TEST_IMAGE):
            refs = assets.references("kind-1.34.11")
        self.assertEqual(refs["operator"], SYNTHETIC["operator_image"])
        self.assertEqual(refs["backend"], SYNTHETIC["backend_image"])
        self.assertEqual(refs["tests"], TEST_IMAGE)
        self.assertEqual({key: refs[key] for key in ("postgres", "seaweed", "python", "agent")}, {key: original[key] for key in ("postgres", "seaweed", "python", "agent")})
        self.assertEqual(assets.legacy.REFERENCES, original)

    def test_archive_path_digest_and_hash_must_agree_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "assets").mkdir()
            path = root / "assets" / "backend.tar"
            files, descriptor, amd, _ = fixture_archive(nested=True)
            raw = tar_bytes(files)
            path.write_bytes(raw)
            owner = SimpleNamespace(root=root)
            ref = "example.invalid/backend@" + descriptor["digest"]
            entry = receipt(path, raw, descriptor, amd)
            with root_file_metadata():
                self.assertEqual(assets.verify_archive(owner, "backend", ref, entry), (raw, assets.archive_graph.sha(files["index.json"])))
                for changed in (dict(entry, path=str(root / "other.tar")), dict(entry, rootDigest="sha256:" + "c" * 64), dict(entry, archiveBytes=True), dict(entry, archiveSHA256="0" * 64), dict(entry, linuxAMD64ManifestDigest="sha256:" + "b" * 64)):
                    with self.subTest(change=changed), self.assertRaises(RuntimeError):
                        assets.verify_archive(owner, "backend", ref, changed)
                arbitrary = b"NOT_AN_OCI_ARCHIVE"
                path.write_bytes(arbitrary)
                with self.assertRaises(RuntimeError):
                    assets.verify_archive(owner, "backend", ref, receipt(path, arbitrary, descriptor, amd))

    def test_hardlink_symlink_or_size_boundary_is_denied_before_payload_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "public.bin"
            path.write_bytes(b"PUBLIC")
            with root_file_metadata(), patch.object(os, "read", side_effect=AssertionError("Must not read")):
                with self.assertRaises(RuntimeError): assets.owned_file(path, 2)
                if os.name == "nt":
                    with patch.object(Path, "resolve", return_value=root / "other.bin"):
                        with self.assertRaisesRegex(RuntimeError, "traverses a link"): assets.owned_file(path, 10)
                else:
                    link = root / "link.bin"
                    link.symlink_to(path)
                    with self.assertRaisesRegex(RuntimeError, "traverses a link"): assets.owned_file(link, 10)
                alias = root / "alias.bin"
                os.link(path, alias)
                with self.assertRaises(RuntimeError): assets.owned_file(path, 10)

    def test_changed_file_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = (Path(temporary) / "public.bin").resolve()
            path.write_bytes(b"PUBLIC")
            original = os.read
            requests = []
            def changed(fd, size):
                requests.append(size)
                raw = original(fd, size)
                if len(requests) == 1:
                    with path.open("ab") as stream:
                        stream.write(b"CHANGED")
                return raw
            with root_file_metadata(), patch.object(os, "read", new=changed), patch.object(os, "close", wraps=os.close) as close:
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    assets.owned_file(path, 100)
                close.assert_called_once()
            self.assertEqual(requests, [7, 1])

    def test_changed_inode_between_lstat_and_open_is_denied_before_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path, replacement = root / "public.bin", root / "replacement.bin"
            path.write_bytes(b"PUBLIC")
            replacement.write_bytes(b"CHANGE")
            original = os.open
            def replace_before_open(filename, flags):
                self.assertEqual(filename, path)
                if os.name != "nt":
                    self.assertTrue(flags & os.O_NOFOLLOW)
                os.replace(replacement, path)
                return original(filename, flags)
            with root_file_metadata(), patch.object(os, "open", new=replace_before_open), \
                    patch.object(os, "read", side_effect=AssertionError("Must not read")), \
                    patch.object(os, "close", wraps=os.close) as close:
                with self.assertRaisesRegex(RuntimeError, "identity changed while opening"):
                    assets.owned_file(path, 100)
                close.assert_called_once()

    def test_all_archives_and_both_clis_checked_before_first_import(self):
        for bad in ("last-archive", "second-cli", "change-after-preflight"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                task = root / "task"
                for directory in (root / "assets", root / "receipts", root / "tools", task / "private"):
                    directory.mkdir(parents=True)
                owner = SimpleNamespace(root=root, task=task, exec=Mock(side_effect=AssertionError("Must not import")))
                files, descriptor, amd, _ = fixture_archive()
                raw = tar_bytes(files)
                roles = ("operator", "backend", "postgres", "seaweed", "python", "agent", "tests")
                refs = {role: "example.invalid/" + role + "@" + descriptor["digest"] for role in roles}
                receipts = {}
                for role in roles:
                    path = root / "assets" / (role + ".tar")
                    payload = b"EXACT_HASH_BUT_NOT_OCI" if bad == "last-archive" and role == "tests" else raw
                    path.write_bytes(payload)
                    receipts[role] = receipt(path, payload, descriptor, amd)
                (root / "receipts" / "public-assets.json").write_bytes(assets.canonical({
                    "format": "sekvyr-stage8-public-assets-v1", "rootTask": str(root), "archives": receipts}))
                elf = static_elf()
                checksum = hashlib.sha256(elf).hexdigest()
                pins = {"recovery_sha256": checksum, "provision_sha256": checksum}
                for name, _ in assets.CLIS:
                    (root / "tools" / ("sekvyr-" + name)).write_bytes(
                        b"INVALID" if bad == "second-cli" and name == "provision" else elf)
                original = assets.verified_cli

                def after_preflight(capability, name, expected):
                    data = original(capability, name, expected)
                    if bad == "change-after-preflight" and name == "provision":
                        (root / "assets" / "operator.tar").write_bytes(b"CHANGED")
                    return data

                with root_file_metadata(), patch.object(assets, "references", return_value=refs), \
                        patch.object(assets, "reviewed", return_value=(None, pins)), \
                        patch.object(assets, "Capability", return_value=owner), \
                        patch.object(assets, "verified_cli", side_effect=after_preflight):
                    with self.assertRaisesRegex(RuntimeError, {"last-archive": "OCI archive exceeds bounds",
                            "second-cli": "Reviewed static amd64 executable", "change-after-preflight": "archive bytes differ"}[bad]):
                        assets.run(None, profile="kind-1.37.0")
                owner.exec.assert_not_called()
                self.assertEqual((task / "private" / "image-imports").exists(), bad == "change-after-preflight")

    def test_static_amd64_hash_does_not_allow_dynamic_loader_or_other_machine(self):
        raw = static_elf()
        checksum = lambda: hashlib.sha256(raw).hexdigest()
        assets.verify_static_cli(raw, checksum())
        with self.assertRaises(RuntimeError): assets.verify_static_cli(raw, "f" * 64)
        struct.pack_into("<I", raw, 64, 3)
        with self.assertRaisesRegex(RuntimeError, "dynamic loader"): assets.verify_static_cli(raw, checksum())
        struct.pack_into("<I", raw, 64, 0)
        struct.pack_into("<H", raw, 18, 183)
        with self.assertRaises(RuntimeError): assets.verify_static_cli(raw, checksum())


if __name__ == "__main__":
    unittest.main()
