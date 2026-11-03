"""Local lifecycle guard tests; real witness rotation is coordinator-run."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import TrialFixture, canonical, issue_leaf, write_private
from panel import Panel
from protocol import ProtocolAuthority
from rotation_cases import save_protocol_version
from witness import config
from witness_rotation import BASE_KEYS, Owned, prepare, rotate_witness


class FakeCluster:
    def __init__(self, task, fixture):
        self.task, self.fixture = task, {"namespaces": fixture.namespaces}
        self.pins = task / "pins"
        self.pins.mkdir()
        self.namespace_uids = {name: str(uuid.uuid4()) for name in fixture.namespaces.values()}
        self.objects, self.calls, self.creations = {}, [], []
        self.conflict = False

    def namespace_pins(self):
        return dict(self.namespace_uids)

    def seed(self, value):
        value = copy.deepcopy(value)
        value["metadata"].update(uid=str(uuid.uuid4()), resourceVersion="1", generation=1)
        if value["kind"] == "Deployment":
            value["status"] = {"readyReplicas": 1, "observedGeneration": 1}
        kind, meta = value["kind"], value["metadata"]
        self.objects[(meta["namespace"], kind, meta["name"])] = value
        write_private(self.pins / (str(uuid.uuid4()) + ".json"), canonical({"apiVersion": value["apiVersion"],
            "kind": kind, "namespace": meta["namespace"], "name": meta["name"], "uid": meta["uid"]}))
        return value

    def create(self, value):
        meta = value["metadata"]
        if (meta["namespace"], value["kind"], meta["name"]) in self.objects:
            raise RuntimeError("Existing unowned resource cannot be adopted")
        self.creations.append(copy.deepcopy(value))
        return self.seed(value)

    def kube(self, *args, data=None, check=True):
        self.calls.append((args, data))
        if args[:2] == ("get", "namespace"):
            value = {"metadata": {"uid": self.namespace_uids[args[2]]}}
        elif args[0] == "get":
            namespace = args[args.index("-n") + 1]
            value = self.objects[(namespace, args[1], args[2])]
        elif args[0] == "patch":
            if self.conflict:
                self.conflict = False
                raise RuntimeError("ResourceVersionConflict")
            namespace = args[args.index("-n") + 1]
            value = self.objects[(namespace, args[1], args[2])]
            operations = json.loads(args[args.index("-p") + 1])
            for operation in operations:
                path = operation["path"].strip("/").split("/")
                parent = value
                for part in path[:-1]:
                    parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                leaf = int(path[-1]) if isinstance(parent, list) else path[-1]
                if operation["op"] == "test":
                    if parent[leaf] != operation["value"]:
                        raise RuntimeError("ResourceVersionConflict")
                elif operation["op"] == "replace":
                    parent[leaf] = copy.deepcopy(operation["value"])
                else:
                    raise AssertionError("Unexpected local patch operation")
            value["metadata"]["resourceVersion"] = str(int(value["metadata"]["resourceVersion"]) + 1)
            value["metadata"]["generation"] += 1
            value["status"] = {"readyReplicas": 1, "observedGeneration": value["metadata"]["generation"]}
        elif args[:2] == ("rollout", "status"):
            return SimpleNamespace(stdout="ready", returncode=0)
        else:
            raise AssertionError("Unexpected local test operation")
        return SimpleNamespace(stdout=json.dumps(copy.deepcopy(value)), returncode=0)


class FakePanel(Panel):
    def connect(self):
        self.connected = True

    def login(self):
        self.authenticated = True

    def unseal(self):
        self.unsealed = True


class WitnessRotationGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        self.fixture = TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)
        self.private = self.task / "private"
        write_private(self.private / "fetch-token", b"public-fixture-fetch-token")
        issue_leaf(self.task, "journal", "witness-server", "server", ["localhost"])
        issue_leaf(self.task, "journal", "panel-server", "server", ["localhost"])
        self.cluster = FakeCluster(self.task, self.fixture)
        namespace = self.fixture.namespaces["witness"]
        for replica in ("witness-a", "witness-b"):
            values = {"journal-ca.crt": (self.private / "journal-ca.crt").read_bytes(),
                "tls.crt": (self.private / "witness-server.crt").read_bytes(), "tls.key": (self.private / "witness-server.key").read_bytes(),
                "client.crt": (self.private / (replica + ".crt")).read_bytes(), "client.key": (self.private / (replica + ".key")).read_bytes(),
                "fetch-token": (self.private / "fetch-token").read_bytes(), "witness.key": (self.protocol.root / "witness.key").read_bytes()}
            self.cluster.seed({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": replica + "-files", "namespace": namespace},
                "type": "Opaque", "immutable": True, "data": {name: base64.b64encode(raw).decode() for name, raw in values.items()}})
            self.cluster.seed({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": replica + "-config", "namespace": namespace},
                "immutable": True, "data": {"config.json": canonical(config(self.protocol, self.fixture.namespaces, replica)).decode()}})
            self.cluster.seed(self.deployment(replica, namespace, [{"name": "files", "secret": {"secretName": replica + "-files", "defaultMode": 288}},
                {"name": "config", "configMap": {"name": replica + "-config"}}], "witness"))
        self.cluster.seed(self.deployment("panel", self.fixture.namespaces["panel"], [{"name": "fixture", "secret": {"secretName": "panel-files"}}], "panel"))
        self.panel = FakePanel(self.cluster, self.protocol, None)
        self.coordinator = SimpleNamespace(cluster=self.cluster, protocol=self.protocol, task=self.task, private=self.private,
            namespaces=self.fixture.namespaces, app=SimpleNamespace(protocol=self.protocol), panel=self.panel,
            witness_forward=Mock(), client=None, witness_origin="https://witness.example.test:8443")
        self.new = save_protocol_version(self.private / "new-witness", self.protocol, "witness")
        self.state = {"scope": self.new.scope, "genesis_hash": self.new.genesis_hash, "authority": self.new.authority,
            "cursor": {"journal_sequence": "6", "record_hash": "a" * 64}}

    @staticmethod
    def deployment(name, namespace, volumes, container):
        return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": namespace},
            "spec": {"replicas": 1, "template": {"metadata": {"labels": {"app": name}}, "spec": {
                "containers": [{"name": container, "image": "example/service@sha256:" + "1" * 64}], "volumes": volumes}}}}

    def rotate(self):
        with patch("witness_rotation.Forward", return_value=SimpleNamespace(origin="https://localhost:12345", close=Mock())), \
             patch("witness_rotation.JournalClient", return_value=SimpleNamespace(origin="https://localhost:12345")):
            return rotate_witness(self.coordinator, self.new, self.state)

    def test_two_replicas_new_materials_preserve_genesis_and_do_not_touch_operator(self):
        result = self.rotate()
        self.assertTrue(result["bothWitnessReplicasReconfigured"])
        self.assertFalse(result["operatorTrustChanged"])
        self.assertIs(self.coordinator.app.protocol, self.protocol)
        self.assertIs(self.panel.protocol, self.new)
        self.assertIs(self.panel.witness_client, self.coordinator.client)
        self.assertTrue(self.panel.connected and self.panel.authenticated and self.panel.unsealed)
        witness_secrets = [item for item in self.cluster.creations if item["kind"] == "Secret" and item["metadata"]["namespace"] == self.fixture.namespaces["witness"]]
        self.assertEqual(len(witness_secrets), 2)
        for secret in witness_secrets:
            self.assertEqual(set(secret["data"]), BASE_KEYS | {"diagnostic-witness.key"})
            self.assertEqual(base64.b64decode(secret["data"]["diagnostic-witness.key"]), (self.protocol.root / "witness.key").read_bytes())
        configs = [json.loads(item["data"]["config.json"]) for item in self.cluster.creations if item["kind"] == "ConfigMap"]
        for cfg in configs:
            self.assertEqual(cfg["registrations"][0]["journal"], self.protocol.registration)
            self.assertEqual(cfg["signing_key_files"], ["/files/witness.key", "/files/diagnostic-witness.key"])
        self.assertFalse(any(item["metadata"]["namespace"] == self.fixture.namespaces["apps"] for item in self.cluster.creations))
        argv = json.dumps([args for args, _ in self.cluster.calls])
        for name in ("admin.key", "publisher.key", "node.key", "witness.key"):
            self.assertNotIn((self.protocol.root / name).read_text().strip(), argv)
        self.assertNotIn("public-fixture-fetch-token", argv)

    def test_retry_exact_input_keeps_same_resource_uids_and_does_not_restart_again(self):
        self.rotate()
        identities = {key: value["metadata"]["uid"] for key, value in self.cluster.objects.items()}
        creations = len(self.cluster.creations)
        patches = sum(args[0] == "patch" for args, _ in self.cluster.calls)
        self.rotate()
        self.assertEqual(len(self.cluster.creations), creations)
        self.assertEqual(sum(args[0] == "patch" for args, _ in self.cluster.calls), patches)
        self.assertEqual({key: value["metadata"]["uid"] for key, value in self.cluster.objects.items()}, identities)
        self.assertEqual(self.panel.revision, 1)

    def test_wrong_scope_or_authority_is_rejected_before_resource_mutation(self):
        self.state["scope"] = dict(self.state["scope"], log_id=str(uuid.uuid4()))
        with self.assertRaisesRegex(RuntimeError, "reviewed"):
            self.rotate()
        self.assertEqual(self.cluster.creations, [])

    def test_replaced_namespace_uid_or_original_secret_uid_is_rejected(self):
        owned = Owned(self.cluster, self.fixture.namespaces["witness"])
        self.cluster.namespace_uids[owned.namespace] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "namespace replaced"):
            owned.get("Secret", "witness-a-files")
        namespace = self.fixture.namespaces["witness"]
        value = self.cluster.objects[(namespace, "Secret", "witness-a-files")]
        value["metadata"]["uid"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "resource replaced"):
            self.rotate()
        self.assertEqual(self.cluster.creations, [])

    def test_unexpected_runtime_credentials_cannot_be_copied_to_new_secret(self):
        value = self.cluster.objects[(self.fixture.namespaces["witness"], "Secret", "witness-a-files")]
        value["data"]["aws-secret-key"] = base64.b64encode(b"public-fixture-unexpected").decode()
        with self.assertRaisesRegex(RuntimeError, "secret shape"):
            self.rotate()
        self.assertEqual(self.cluster.creations, [])

    def test_cas_conflict_retries_same_prepared_inputs_without_new_keys_or_names(self):
        self.cluster.conflict = True
        with self.assertRaisesRegex(RuntimeError, "Conflict"):
            self.rotate()
        prepared = (self.private / "witness-rotation-2" / "prepared.json").read_bytes()
        self.rotate()
        self.assertEqual((self.private / "witness-rotation-2" / "prepared.json").read_bytes(), prepared)
        self.assertEqual(len([item for item in self.cluster.creations if item["kind"] == "Secret"]), 3)

    def test_unpinned_existing_material_is_never_adopted(self):
        owned = Owned(self.cluster, self.fixture.namespaces["witness"])
        plan = prepare(self.coordinator, self.new, self.state, owned)
        value = copy.deepcopy(plan["replicas"][0]["secret"])
        value["metadata"]["uid"] = str(uuid.uuid4())
        self.cluster.objects[(owned.namespace, "Secret", value["metadata"]["name"])] = value
        with self.assertRaisesRegex(RuntimeError, "cannot be adopted"):
            self.rotate()
        self.assertEqual(self.cluster.creations, [])

    def test_modified_prepared_key_or_cursor_is_not_silently_rebased(self):
        self.cluster.conflict = True
        with self.assertRaises(RuntimeError):
            self.rotate()
        self.state = dict(self.state, cursor={"journal_sequence": "7", "record_hash": "b" * 64})
        before = len(self.cluster.creations)
        with self.assertRaisesRegex(RuntimeError, "exact prepared input"):
            self.rotate()
        self.assertEqual(len(self.cluster.creations), before)


if __name__ == "__main__":
    unittest.main()
