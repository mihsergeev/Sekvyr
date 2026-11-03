"""Local scanner guard tests; generated fixture keys never leave temp memory."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import TrialFixture, canonical, write_private
from log_privacy import Inventory, MAX_LOG, collect, scan
from protocol import ProtocolAuthority, b64


class FakeCluster:
    def __init__(self, task, fixture):
        self.task, self.config = task, task / "kubeconfig"
        self.fixture = {"namespaces": fixture.namespaces}
        self.pins = task / "pins"
        self.pins.mkdir()
        self.pinned = {name: str(uuid.uuid4()) for name in fixture.namespaces.values()}
        self.live = dict(self.pinned)
        self.calls, self.logs, self.resources = [], {}, {}
        self.namespace = fixture.namespaces["apps"]
        self.pod = {"kind": "Pod", "metadata": {"name": "own-app", "namespace": self.namespace, "uid": str(uuid.uuid4())},
            "spec": {"containers": [{"name": "app"}], "initContainers": [{"name": "init"}], "ephemeralContainers": [{"name": "debug"}]},
            "status": {"containerStatuses": [{"name": "app", "containerID": "current-app", "restartCount": 1,
                "lastState": {"terminated": {"containerID": "previous-app"}}}],
                "initContainerStatuses": [{"name": "init", "containerID": "current-init", "restartCount": 0}],
                "ephemeralContainerStatuses": [{"name": "debug", "containerID": "current-debug", "restartCount": 0}]}}
        self.replace_after_log = False
        for kind, name in (("SekvyrStore", "trial-store"), ("SekvyrSecret", "trial-source")):
            uid = str(uuid.uuid4())
            self.resources[(kind, name)] = {"kind": kind, "metadata": {"name": name, "namespace": self.namespace, "uid": uid},
                "spec": {"private-test-only": "public-fixture-admin-password"}, "status": {"ready": False, "reason": "ScaffoldOnly"}}
            write_private(self.pins / (kind + ".json"), canonical({"kind": kind, "name": name, "namespace": self.namespace, "uid": uid}))

    def namespace_pins(self):
        return dict(self.pinned)

    def kube(self, *args):
        self.calls.append(args)
        if args[:2] == ("get", "namespace"):
            value = {"metadata": {"name": args[2], "uid": self.live[args[2]]}}
        elif args[:2] == ("get", "pods"):
            value = {"items": [self.pod] if args[args.index("-n") + 1] == self.namespace else []}
        elif args[:2] == ("get", "pod"):
            value = self.pod
        elif args[0] == "logs":
            key = (args[args.index("-c") + 1], "--previous" in args)
            raw = self.logs.get(key, "ordinary initial public status\n")
            if isinstance(raw, Exception):
                raise raw
            if self.replace_after_log:
                self.pod["metadata"]["uid"] = str(uuid.uuid4())
            return SimpleNamespace(stdout=raw, returncode=0)
        elif args[0] == "get":
            value = self.resources[(args[1], args[2])]
        else:
            raise AssertionError("Unexpected privacy test operation")
        return SimpleNamespace(stdout=json.dumps(copy.deepcopy(value)), returncode=0)


class LogPrivacyGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        self.fixture = TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)
        self.private = self.task / "private"
        write_private(self.private / "database-password", b"public-fixture-database-password")
        write_private(self.private / "fetch-token", b"public-fixture-fetch-credential")
        write_private(self.private / "panel-access.json", canonical({"SEKVYR_ADMIN_PASSWORD": "public-fixture-admin-password",
            "SEKVYR_JWT_SECRET": "public-fixture-jwt-signing-secret", "SEKVYR_DB_URL": "postgresql+asyncpg://trial:public-fixture-database-password@database/trial_panel"}))
        write_private(self.private / "panel-vault-key.json", canonical({"root_key": b64(b"public-fixture-vault-key-32bytes!")}))
        self.cluster = FakeCluster(self.task, self.fixture)
        write_private(self.cluster.config, canonical({"users": [{"name": "private-test-client", "user": {
            "client-key-data": base64.b64encode((self.private / "admin.key").read_bytes()).decode()}}]}))
        self.canary = "public-privacy-canary-" + uuid.uuid4().hex
        self.target = {"data": {"GENERATION": base64.b64encode(b"initial").decode(), "DEMO_VALUE": base64.b64encode(self.canary.encode()).decode()}}
        self.c = SimpleNamespace(task=self.task, private=self.private, cluster=self.cluster,
            app=SimpleNamespace(get=lambda kind, name: self.target))

    def test_complete_scope_and_current_previous_init_ephemeral_logs_status_only(self):
        result = scan(self.c)
        self.assertTrue(result["complete"])
        self.assertEqual(result["confirmedLeaks"], 0)
        self.assertEqual(result["logStreams"], 4)
        self.assertEqual(result["statusObjects"], 2)
        self.assertGreater(result["secretCount"], 0)
        self.assertGreater(result["knownPatterns"], result["secretCount"])
        log_calls = [args for args in self.cluster.calls if args[0] == "logs"]
        self.assertEqual(sum("--previous" in args for args in log_calls), 1)
        self.assertTrue(all("--limit-bytes=" + str(MAX_LOG) in args for args in log_calls))
        for args in self.cluster.calls:
            if "-n" in args:
                self.assertIn(args[args.index("-n") + 1], self.cluster.pinned)
        self.assertTrue(all(type(value) in (int, bool) for value in result.values()))

    def test_known_credentials_canaries_read_key_edseed_and_ecscalar_are_detected(self):
        inventory = collect(self.c)
        edseed = self.protocol.publisher.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        ec_key = serialization.load_pem_private_key((self.private / "journal-ca.key").read_bytes(), password=None)
        scalar = ec_key.private_numbers().private_value.to_bytes(32, "big")
        for raw in (b"public-fixture-admin-password", self.canary.encode(), base64.b64encode(self.protocol.read_key),
                    edseed.hex().encode(), base64.urlsafe_b64encode(scalar).rstrip(b"=")):
            with self.subTest(length=len(raw)):
                self.assertTrue(inventory.matches(b"untrusted log: " + raw))
        self.cluster.logs[("debug", False)] = "message=" + self.canary
        result = scan(self.c)
        self.assertTrue(result["complete"])
        self.assertEqual(result["confirmedLeaks"], 1)
        self.assertNotIn(self.canary, json.dumps(result))

    def test_unpersisted_jwt_and_unknown_private_key_anchor_are_detected(self):
        inventory = Inventory()
        token = b64(canonical({"alg": "HS256", "typ": "JWT"})) + "." + b64(canonical({"sub": "public-fixture-identity", "aud": "trial"})) + "." + b64(b"x" * 32)
        self.assertTrue(inventory.matches(token.encode()))
        self.assertTrue(inventory.matches(b"prefix -----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertFalse(inventory.matches(b"-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----"))

    def test_public_certificate_and_short_initial_word_are_not_classified_as_secrets(self):
        inventory = collect(self.c)
        self.assertFalse(inventory.matches((self.private / "journal-ca.crt").read_bytes()))
        self.assertFalse(inventory.matches((self.private / "admin.crt").read_bytes()))
        self.assertFalse(inventory.matches(b"initial setup completed with public certificate"))
        self.assertTrue(inventory.matches(b"public-trial-initial"))

    def test_truncation_unavailable_previous_or_changed_pod_prevents_complete(self):
        self.cluster.logs[("app", True)] = "x" * MAX_LOG
        result = scan(self.c)
        self.assertFalse(result["complete"])
        self.assertEqual(result["truncatedStreams"], 1)
        self.cluster.logs[("app", True)] = RuntimeError("private-response-must-not-appear")
        result = scan(self.c)
        self.assertFalse(result["complete"])
        self.assertGreater(result["incompleteStreams"], 0)
        self.assertNotIn("private-response", json.dumps(result))
        self.cluster.logs.clear()
        self.cluster.replace_after_log = True
        result = scan(self.c)
        self.assertFalse(result["complete"])
        self.assertGreater(result["incompleteStreams"], 0)

    def test_foreign_namespace_or_replaced_cr_is_not_scanned(self):
        self.cluster.live[self.cluster.namespace] = str(uuid.uuid4())
        result = scan(self.c)
        self.assertFalse(result["complete"])
        self.assertFalse(any(args[0] == "logs" for args in self.cluster.calls))
        self.cluster.live = dict(self.cluster.pinned)
        self.cluster.resources[("SekvyrSecret", "trial-source")]["metadata"]["uid"] = str(uuid.uuid4())
        self.assertFalse(scan(self.c)["complete"])

    def test_private_scan_does_not_open_outside_signing_key_and_requires_all_inventory_inputs(self):
        outside = self.task / "agent-signing-key"
        write_private(outside, b"public-external-signing-marker")
        self.assertFalse(collect(self.c).matches(b"public-external-signing-marker"))
        (self.private / "panel-vault-key.json").unlink()
        result = scan(self.c)
        self.assertFalse(result["complete"])
        self.assertEqual(result["logStreams"], 0)

    def test_versioned_json_canaries_and_status_leak_are_detected_without_spec_false_positive(self):
        future = "public-future-demo-" + uuid.uuid4().hex
        write_private(self.private / "future.json", canonical({"generation": "post-rotation-" + uuid.uuid4().hex,
            "envelope": {}, "hash": "a" * 64, "value": future}))
        self.cluster.resources[("SekvyrStore", "trial-store")]["status"] = {"message": future}
        result = scan(self.c)
        self.assertTrue(result["complete"])
        self.assertEqual(result["confirmedLeaks"], 1)
        self.assertNotIn(future, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
