import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import runtime_privacy as privacy


class RuntimePrivacyTests(unittest.TestCase):
    def fixture(self, root, events=None):
        namespaces = {role: "trial-" + role for role in privacy.ROLES}
        pins = {name: "uid-" + name for name in namespaces.values()}
        for index, kind in enumerate(("SekvyrStore", "SekvyrSecret")):
            (root / (str(index) + ".json")).write_text(json.dumps({"namespace": namespaces["apps"], "kind": kind, "name": "owned", "uid": "uid-owned"}))
        def kube(*args):
            if args[:2] == ("get", "pods"):
                return SimpleNamespace(stdout=json.dumps({"items": []}))
            if args[:2] == ("get", "events"):
                namespace = args[args.index("-n") + 1]
                value = {"kind": "Event", "metadata": {"namespace": namespace, "uid": "event-uid"}, "message": "safe"}
                if events:
                    value = events(value)
                return SimpleNamespace(stdout=json.dumps({"items": [value]}))
            if args[0] == "get" and args[1] in ("SekvyrStore", "SekvyrSecret"):
                return SimpleNamespace(stdout=json.dumps({"kind": args[1], "metadata": {"namespace": namespaces["apps"], "uid": "uid-owned"}, "status": {"reason": "safe"}}))
            raise AssertionError("Unexpected scan query")
        return SimpleNamespace(private=root, cluster=SimpleNamespace(fixture={"namespaces": namespaces}, namespace_pins=lambda: pins, pins=root, kube=kube))

    def scan(self, coordinator, memory=()):
        inventory = privacy._base.Inventory()
        with patch.object(privacy._base, "collect", return_value=inventory), patch.object(privacy._base, "namespace_guard"), patch.object(privacy, "_events", side_effect=lambda cluster, namespace: cluster.kube("get", "events", "-n", namespace).stdout.encode()):
            return privacy.scan(coordinator, memory)

    def test_six_namespaces_all_events_and_cr_status(self):
        with TemporaryDirectory() as path:
            result = self.scan(self.fixture(Path(path)))
        self.assertTrue(result["complete"])
        self.assertEqual((result["eventObjects"], result["statusObjects"], result["confirmedLeaks"]), (6, 2, 0))

    def test_event_secret_match_only_exposes_counts(self):
        secret = "synthetic-memory-credential-abcdef"
        with TemporaryDirectory() as path:
            result = self.scan(self.fixture(Path(path), lambda event: dict(event, message=secret)), [secret])
        self.assertTrue(result["complete"])
        self.assertEqual(result["confirmedLeaks"], 6)
        self.assertNotIn(secret, json.dumps(result))

    def test_signer_rollover_pem_seed_is_included(self):
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        with TemporaryDirectory() as path:
            root = Path(path)
            (root / "new-key.pem").write_bytes(pem)
            result = self.scan(self.fixture(root, lambda event: dict(event, message=base64.b64encode(seed).decode())))
        self.assertTrue(result["complete"])
        self.assertEqual(result["confirmedLeaks"], 6)

    def test_wrong_event_namespace_is_incomplete(self):
        with TemporaryDirectory() as path:
            result = self.scan(self.fixture(Path(path), lambda event: dict(event, metadata={"namespace": "foreign", "uid": "uid"})))
        self.assertFalse(result["complete"])
        self.assertEqual(result["incompleteStreams"], 6)

    def test_event_truncation_cannot_pass(self):
        with TemporaryDirectory() as path:
            result = self.scan(self.fixture(Path(path), lambda event: dict(event, message="x" * privacy._base.MAX_LOG)))
        self.assertFalse(result["complete"])
        self.assertEqual(result["truncatedStreams"], 6)

    def test_event_pipe_stops_and_reaps_at_byte_limit(self):
        process = MagicMock()
        process.poll.return_value = None
        process.wait.return_value = 0
        selected = MagicMock()
        selected.__enter__.return_value = selected
        selected.select.return_value = [True]
        cluster = SimpleNamespace(kubectl="/private/kubectl", config="/private/kubeconfig")
        with patch.object(privacy.subprocess, "Popen", return_value=process) as spawn, patch.object(privacy.selectors, "DefaultSelector", return_value=selected), patch.object(privacy.os, "read", side_effect=lambda fd, size: b"x" * size):
            raw = privacy._events(cluster, "trial-owned")
        self.assertEqual(len(raw), privacy._base.MAX_LOG)
        process.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)
        argv = spawn.call_args.args[0]
        self.assertEqual(argv[:3], ["/private/kubectl", "--kubeconfig", "/private/kubeconfig"])
        self.assertIn("--request-timeout=20s", argv)

    def test_event_pipe_timeout_reaps_only_own_process(self):
        process = MagicMock()
        process.poll.return_value = None
        selected = MagicMock()
        selected.__enter__.return_value = selected
        with patch.object(privacy.subprocess, "Popen", return_value=process), patch.object(privacy.selectors, "DefaultSelector", return_value=selected), patch.object(privacy.time, "monotonic", side_effect=[0, 26]):
            with self.assertRaises(RuntimeError):
                privacy._events(SimpleNamespace(kubectl="/private/kubectl", config="/private/kubeconfig"), "trial-owned")
        process.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
