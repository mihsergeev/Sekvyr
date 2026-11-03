"""Pure local guards: no Docker, setns, chroot or Kubernetes execution."""

import ast
import base64
import copy
import json
from pathlib import Path
import struct
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import yaml

import kind_recovery as recovery
from test_plain_installation import public_ca
from plain_installation import canonical


def configs():
    # Synthetically generated only. The pair is used to test correspondence,
    # not to grant a certificate any actual cluster permissions.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Public synthetic admin")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(
        now - timedelta(days=1)).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    b64 = lambda value: base64.b64encode(value).decode()
    value = {"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "owned", "cluster": {
        "server": "https://127.0.0.1:12345", "certificate-authority-data": b64(public_ca())}}],
        "users": [{"name": "admin", "user": {"client-certificate-data": b64(cert), "client-key-data": b64(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))}}],
        "contexts": [{"name": "owned", "context": {"cluster": "owned", "user": "admin"}}], "current-context": "owned"}
    return value


class ConfigGuards(unittest.TestCase):
    def test_only_server_changes_after_ca_cert_key_correspondence(self):
        value = configs()
        native = copy.deepcopy(value)
        native["clusters"][0]["cluster"]["server"] = "https://192.0.2.10:6443"
        output = yaml.safe_load(recovery.recovery_kubeconfig(yaml.safe_dump(value).encode(), yaml.safe_dump(native).encode()))
        value["clusters"][0]["cluster"]["server"] = "https://127.0.0.1:6443"
        self.assertEqual(output, value)

    def test_no_proxy_tls_downgrade_or_credential_helper(self):
        original = configs()
        for field, payload in (("proxy-url", "https://proxy.example.invalid"), ("insecure-skip-tls-verify", True)):
            value = copy.deepcopy(original)
            value["clusters"][0]["cluster"][field] = payload
            with self.assertRaises(RuntimeError):
                recovery.recovery_kubeconfig(yaml.safe_dump(value).encode(), yaml.safe_dump(original).encode())
        value = copy.deepcopy(original)
        value["users"][0]["user"]["exec"] = {"command": "forbidden"}
        with self.assertRaises(RuntimeError):
            recovery.recovery_kubeconfig(yaml.safe_dump(value).encode(), yaml.safe_dump(original).encode())

    def test_different_node_credentials_or_ca_rejected(self):
        original, other = configs(), configs()
        with self.assertRaisesRegex(RuntimeError, "creator-pinned"):
            recovery.recovery_kubeconfig(yaml.safe_dump(original).encode(), yaml.safe_dump(other).encode())
        value = copy.deepcopy(original)
        value["clusters"][0]["cluster"]["certificate-authority-data"] = base64.b64encode(public_ca()).decode()
        with self.assertRaisesRegex(RuntimeError, "creator-pinned"):
            recovery.recovery_kubeconfig(yaml.safe_dump(original).encode(), yaml.safe_dump(value).encode())

    def test_malformed_credential_yaml_never_survives_error_or_traceback(self):
        canary = "SYNTHETIC_CREDENTIAL_MUST_NOT_APPEAR"
        try:
            recovery._config(("users: [\n  token: " + canary + "\n").encode())
        except RuntimeError as error:
            self.assertNotIn(canary, str(error))
            self.assertNotIn(canary, "".join(traceback.format_exception(error)))
        else:
            self.fail("Malformed input accepted")
        with patch.object(recovery, "_recover", side_effect=ValueError(canary)):
            try:
                recovery.recover(None, None, None, None, None)
            except RuntimeError as error:
                self.assertNotIn(canary, "".join(traceback.format_exception(error)))

    def test_public_error_keeps_only_safe_termination_fact(self):
        for confirmed in (True, False):
            unsafe = RuntimeError("SYNTHETIC_CREDENTIAL_MUST_NOT_APPEAR")
            unsafe.termination_confirmed = confirmed
            with patch.object(recovery, "_recover", side_effect=unsafe):
                try:
                    recovery.recover(None, None, None, None, None)
                except RuntimeError as error:
                    self.assertIs(error.termination_confirmed, confirmed)
                    self.assertNotIn("SYNTHETIC_CREDENTIAL", "".join(traceback.format_exception(error)))
                else:
                    self.fail("Recovery failure was hidden")

    def test_static_elf_and_exact_reviewed_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "tools").mkdir()
            (task / "private").mkdir()
            executable = task / "tools" / "sekvyr-checkpoint-recovery"
            raw = bytearray(120)
            raw[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", raw, 18, 62)
            struct.pack_into("<Q", raw, 32, 64)
            struct.pack_into("<H", raw, 54, 56)
            struct.pack_into("<H", raw, 56, 1)
            struct.pack_into("<I", raw, 64, 1)
            executable.write_bytes(raw)
            proof = {"image": "example.invalid/operator@" + recovery.IMAGE_DIGEST, "sha256": recovery.sha(raw)}
            (task / "private" / "recovery-binary.json").write_bytes(canonical(proof))
            panel = SimpleNamespace(task=task, recovery_executable=executable)
            with patch.object(recovery, "CLI_SHA256", recovery.sha(raw)):
                self.assertEqual(recovery.verified_cli(panel), raw)
                executable.write_bytes(raw + b"tamper")
                with self.assertRaises(RuntimeError):
                    recovery.verified_cli(panel)
            struct.pack_into("<I", raw, 64, 3)
            executable.write_bytes(raw)
            proof["sha256"] = recovery.sha(raw)
            (task / "private" / "recovery-binary.json").write_bytes(canonical(proof))
            with patch.object(recovery, "CLI_SHA256", recovery.sha(raw)), self.assertRaisesRegex(RuntimeError, "loader"):
                recovery.verified_cli(panel)


class NetworkFDGuards(unittest.TestCase):
    def join(self, stat_hook=None, guard_hook=None):
        self.joined, self.closed, self.guards = [], [], 0
        state = SimpleNamespace(st_dev=7, st_ino=11)
        calls = []
        def stat(path):
            calls.append(path)
            return stat_hook(len(calls), state) if stat_hook else state
        fake = SimpleNamespace(O_RDONLY=0, O_CLOEXEC=1, CLONE_NEWNET=0x40000000,
            stat=stat, open=lambda path, mode: 52, fstat=lambda fd: state,
            setns=lambda fd, mode: self.joined.append((fd, mode)), close=lambda fd: self.closed.append(fd))
        def need(value):
            if not value:
                raise RuntimeError("Rejected")
        def guard():
            self.guards += 1
            if guard_hook:
                guard_hook(self.guards)
        scope = {"os": fake, "need": need}
        exec(compile(recovery.NET_JOIN, "reviewed-child-network-setup", "exec"), scope)
        scope["join_network"]({"pid": 123}, guard)

    def test_fixed_fd_and_only_network_type_after_repeated_identity_guards(self):
        self.join()
        self.assertEqual(self.joined, [(52, 0x40000000)])
        self.assertEqual(self.closed, [52])
        self.assertEqual(self.guards, 3)

    def test_inode_change_between_open_and_stat_blocks_setns(self):
        with self.assertRaises(RuntimeError):
            self.join(stat_hook=lambda count, old: SimpleNamespace(st_dev=7, st_ino=12) if count == 2 else old)
        self.assertEqual(self.joined, [])
        self.assertEqual(self.closed, [52])

    def test_pid_or_cid_change_after_fd_open_blocks_setns(self):
        def changed(count):
            if count == 2:
                raise RuntimeError("Owner replaced")
        with self.assertRaises(RuntimeError):
            self.join(guard_hook=changed)
        self.assertEqual(self.joined, [])
        self.assertEqual(self.closed, [52])

    def test_namespace_change_immediately_before_setns_blocks(self):
        with self.assertRaises(RuntimeError):
            self.join(stat_hook=lambda count, old: SimpleNamespace(st_dev=7, st_ino=12) if count == 4 else old)
        self.assertEqual(self.joined, [])
        self.assertEqual(self.closed, [52])

    def test_parent_has_no_namespace_or_chroot_calls_and_setup_is_fixed_stdlib(self):
        source = Path(recovery.__file__).read_text(encoding="utf-8")
        parent = ast.parse(source)
        calls = [node for node in ast.walk(parent) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        self.assertFalse(any(node.func.attr in ("setns", "chroot") for node in calls))
        setup = ast.parse(recovery.ROOT_SETUP)
        modules = [alias.name for node in ast.walk(setup) if isinstance(node, ast.Import) for alias in node.names]
        self.assertEqual(set(modules), {"hashlib", "json", "os", "pathlib", "subprocess"})


class CleanupGuards(unittest.TestCase):
    def test_unconfirmed_child_keeps_inputs_confirmed_child_cleans_exact_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            sandbox = task / "private" / ("kind-recovery-" + "1" * 32)
            sandbox.mkdir(parents=True)
            (sandbox / "kubeconfig").write_bytes(b"synthetic-private-input")
            info = sandbox.stat()
            identity = info.st_dev, info.st_ino
            self.assertFalse(recovery.cleanup_sandbox(task, sandbox, identity, False))
            self.assertTrue(sandbox.is_dir())
            self.assertTrue(recovery.cleanup_sandbox(task, sandbox, identity, True))
            self.assertFalse(sandbox.exists())

    def test_replaced_cleanup_identity_never_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            sandbox = task / "private" / ("kind-recovery-" + "1" * 32)
            sandbox.mkdir(parents=True)
            info = sandbox.stat()
            sandbox.rename(sandbox.with_name("saved-owned"))
            sandbox.mkdir()
            with self.assertRaises(RuntimeError):
                recovery.cleanup_sandbox(task, sandbox, (info.st_dev, info.st_ino), True)
            self.assertTrue(sandbox.is_dir())


if __name__ == "__main__":
    unittest.main()
