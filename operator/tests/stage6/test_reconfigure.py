"""Fake API exercises mutation guards/resume; does not claim actual HA E2E."""

import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from application import APP, RELEASE, REVISION, TARGET, Application
from cluster import Cluster
from fixture import TrialFixture, canonical
from protocol import ProtocolAuthority, key_descriptor
from reconfigure import Reconfiguration, _role_shape, next_trust_bundle
import test_application_guards as application_guards


class RuntimeCluster(application_guards.FakeCluster):
    guard_hash = staticmethod(Cluster.guard_hash)

    def __init__(self, task, fixture):
        super().__init__(task, fixture)
        self.guard_chain = {}

    def cluster_creation_pins(self):
        return [value for path in self.pins.glob("*.json") for value in [json.loads(path.read_text())]
            if not value["namespace"] and value["kind"] != "Namespace"]

    def active_cluster_guard(self, pin):
        return self.guard_chain.get(pin["uid"], pin["guardHash"])

    def update_cluster_webhook(self, resource):
        key = resource["kind"], resource["metadata"]["name"]
        current = self.objects[key]
        pin = next(value for value in self.cluster_creation_pins() if (value["kind"], value["name"]) == key)
        if self.guard_hash(current) == self.guard_hash(resource):
            return current
        if self.guard_hash(current) != self.active_cluster_guard(pin) or current["metadata"]["uid"] != pin["uid"]:
            raise RuntimeError("Fake webhook changed")
        result = copy.deepcopy(resource)
        result["metadata"] = copy.deepcopy(current["metadata"])
        result["metadata"]["resourceVersion"] = str(int(current["metadata"]["resourceVersion"]) + 1)
        self.objects[key] = result
        self.guard_chain[pin["uid"]] = self.guard_hash(result)
        return result

    def kube(self, *args, data=None, check=True):
        if args[:2] == ("replace", "--dry-run=server"):
            self.calls.append((args, data))
            value = json.loads(data)
            return SimpleNamespace(stdout=json.dumps(value), returncode=0)
        if "rollout" in args:
            self.calls.append((args, data))
            return SimpleNamespace(stdout="ready", returncode=0)
        if args[:2] in (("get", "replicasets"), ("get", "pods")):
            self.calls.append((args, data))
            selector = args[args.index("-l") + 1]
            name = APP if selector == "app=" + APP else RELEASE + "-operator"
            uid = self.objects[("Deployment", name)]["metadata"]["uid"]
            values = [] if args[1] == "pods" else [{"metadata": {"uid": "rs-" + uid,
                "ownerReferences": [{"kind": "Deployment", "uid": uid}]}}]
            return SimpleNamespace(stdout=json.dumps({"items": values}), returncode=0)
        if args[0] != "patch":
            return super().kube(*args, data=data, check=check)
        self.calls.append((args, data))
        key = args[1], args[2]
        value = copy.deepcopy(self.objects[key])
        operations = json.loads(args[args.index("-p") + 1])
        for operation in operations:
            components = [item.replace("~1", "/").replace("~0", "~") for item in operation["path"].split("/")[1:]]
            parent = value
            for component in components[:-1]:
                parent = parent[int(component)] if isinstance(parent, list) else parent[component]
            index = int(components[-1]) if isinstance(parent, list) else components[-1]
            if operation["op"] == "test":
                if parent[index] != operation["value"]:
                    raise RuntimeError("Fake CAS conflict")
            elif operation["op"] == "remove":
                del parent[index]
            else:
                parent[index] = copy.deepcopy(operation["value"])
        value["metadata"]["resourceVersion"] = str(int(value["metadata"]["resourceVersion"]) + 1)
        self.objects[key] = value
        return SimpleNamespace(stdout=json.dumps(value), returncode=0)


@unittest.skipUnless(os.environ.get("HELM_BIN"), "Real Helm render required")
class ReconfigureGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        fixture = TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)
        self.cluster = RuntimeCluster(self.task, fixture)
        self.app = Application(self.cluster, self.protocol)
        materials, self.snapshot, _ = application_guards.ApplicationGuards.prepared(self)
        self.values = self.app.chart_values("example/operator@sha256:" + "c" * 64,
            {"username": "trial-bootstrap", "uid": ""}, "https://journal.example.test", materials["journal_ca"])
        self.helm, self.chart = os.environ["HELM_BIN"], HERE.parents[1] / "charts" / "sekvyr-operator"
        self.app.install_chart(self.values, self.helm, self.chart)

    def reconfiguration(self, name="recovery-2"):
        return Reconfiguration(self.app, self.helm, self.chart, self.values, name)

    def trust(self, generation):
        value = json.loads(base64.b64decode(self.app.get("Secret", self.app.trust_name)["data"]["trust.json"]))
        value["bootstrapGeneration"] = generation
        return value

    def test_stop_guard_rejects_unreviewed_role_or_deployment_change(self):
        role = self.cluster.objects[("Role", RELEASE + "-operator")]
        role["rules"].append({"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]})
        job = self.reconfiguration()
        with self.assertRaisesRegex(RuntimeError, "Role differs"):
            job.stop_operator()
        self.assertEqual(self.app.get("Deployment", RELEASE + "-operator")["spec"]["replicas"], 2)

    def test_prepare_requires_stopped_operator_and_explicit_same_inputs(self):
        job = self.reconfiguration()
        with self.assertRaisesRegex(RuntimeError, "Stop operator"):
            job.prepare(2, self.protocol, self.protocol.node, self.trust(2), self.protocol.fencer)
        job.stop_operator()
        enrollment = job.prepare(2, self.protocol, self.protocol.node, self.trust(2), self.protocol.fencer)
        self.assertEqual(enrollment["bootstrap_generation"], 2)
        self.assertEqual(self.app.node_secret_name, "operator-node-r2")
        trust = self.trust(2)
        trust["viewTrust"][0]["minimumCheckpoint"]["envelopeHash"] = "b" * 64
        with self.assertRaisesRegex(RuntimeError, "inputs changed"):
            job.prepare(2, self.protocol, self.protocol.node, trust, self.protocol.fencer)

    def test_full_reconfiguration_preserves_app_and_requires_signed_complete_state(self):
        job = self.reconfiguration()
        job.stop_operator()
        original = job.plan["applicationInvariant"]
        trust = self.trust(2)
        enrollment = job.prepare(2, self.protocol, self.protocol.node, trust, self.protocol.fencer)
        values = self.app.chart_values("example/operator@sha256:" + "c" * 64,
            {"username": "trial-bootstrap", "uid": ""}, "https://journal.example.test", self.app.materials["journal_ca"])
        current = {"scope": self.protocol.scope, "genesis_hash": self.protocol.genesis_hash,
            "enrollments": {self.protocol.installation_id: enrollment}, "authority": self.protocol.authority}
        installation = job.apply(values, current)
        self.assertEqual(installation["bootstrapGeneration"], 2)
        self.assertEqual(installation["identityKeySecret"]["name"], "operator-node-r2")
        self.assertEqual(self.app.get("Deployment", RELEASE + "-operator")["spec"]["replicas"], 0)
        self.assertEqual(job._application_invariant(), original)
        hook = next(value for key, value in self.cluster.objects.items() if key[0] == "ValidatingWebhookConfiguration")
        expression = hook["webhooks"][0]["matchConditions"][0]["expression"]
        self.assertIn('"operator-state"', expression)
        self.assertIn('"operator-state-r2"', expression)
        patch_count = sum(args[0] == "patch" for args, _ in self.cluster.calls)
        self.assertEqual(job.apply(values, current), installation)
        self.assertEqual(sum(args[0] == "patch" for args, _ in self.cluster.calls), patch_count)
        with self.assertRaises((RuntimeError, KeyError)):
            job.resume_operator()
        state = self.cluster.objects[("Secret", self.app.state_name)]
        state["data"]["state.json"] = base64.b64encode(canonical({"installationID": self.protocol.installation_id,
            "bootstrapGeneration": 2, "recovery": {"phase": "complete"}})).decode()
        job.resume_operator()
        self.assertEqual(self.app.get("Deployment", RELEASE + "-operator")["spec"]["replicas"], 2)

    def test_generation_three_rotated_node_signer_and_all_old_webhook_names_survive(self):
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        protocol = copy.copy(self.protocol)
        protocol.node = ec.generate_private_key(ec.SECP256R1())
        protocol.publisher, protocol.witness, protocol.fencer = [ed25519.Ed25519PrivateKey.generate() for _ in range(3)]
        protocol.authority = copy.deepcopy(self.protocol.authority)
        protocol.authority.update(publisher_policy_epoch="2", publisher_keys=[key_descriptor(protocol.publisher)],
            witness_epoch="2", witness_key=key_descriptor(protocol.witness), fencer_epoch="2", fencer_keys=[key_descriptor(protocol.fencer)])
        job = self.reconfiguration("rotation-3")
        job.stop_operator()
        trust = next_trust_bundle(self.app, protocol, 3, self.snapshot)
        enrollment = job.prepare(3, protocol, protocol.node, trust, protocol.fencer)
        values = self.app.chart_values("example/operator@sha256:" + "c" * 64,
            {"username": "trial-bootstrap", "uid": ""}, "https://journal.example.test", self.app.materials["journal_ca"])
        current = {"scope": protocol.scope, "genesis_hash": protocol.genesis_hash,
            "enrollments": {protocol.installation_id: enrollment}, "authority": protocol.authority}
        installation = job.apply(values, current)
        self.assertEqual(installation["identityKeySecret"]["name"], "operator-node-r3")
        self.assertNotEqual(self.app.get("Secret", "operator-node")["data"], self.app.get("Secret", "operator-node-r3")["data"])
        self.assertNotEqual(self.app.get("Secret", "fencer-signing")["data"], self.app.get("Secret", "fencer-signing-r3")["data"])
        hook = next(value for key, value in self.cluster.objects.items() if key[0] == "ValidatingWebhookConfiguration")
        expression = hook["webhooks"][0]["matchConditions"][0]["expression"]
        self.assertIn('"operator-state"', expression)
        self.assertIn('"operator-state-r3"', expression)
        self.assertEqual(self.app.get("Deployment", RELEASE + "-operator")["spec"]["replicas"], 0)

    def test_resume_constructor_reuses_exact_progress_and_refuses_new_values(self):
        job = self.reconfiguration()
        job.stop_operator()
        job.prepare(2, self.protocol, self.protocol.node, self.trust(2), self.protocol.fencer)
        loaded = Application(self.cluster, self.protocol)
        self.assertEqual(loaded.generation, 2)
        resumed = Reconfiguration(loaded, self.helm, self.chart, self.values, "recovery-2")
        self.assertEqual(resumed.plan["phase"], "prepared")
        self.assertEqual(resumed.plan["prepared"], job.plan["prepared"])
        changed = copy.deepcopy(self.values)
        changed["replicas"] = 3
        with self.assertRaisesRegex(RuntimeError, "overwrite refused"):
            Reconfiguration(loaded, self.helm, self.chart, changed, "recovery-2")

    def test_role_shape_rejects_broadening_and_new_material_never_in_values(self):
        narrow = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["old"]}]
        renamed = copy.deepcopy(narrow)
        renamed[0]["resourceNames"] = ["new"]
        self.assertEqual(_role_shape(narrow), _role_shape(renamed))
        broad = copy.deepcopy(narrow)
        del broad[0]["resourceNames"]
        self.assertNotEqual(_role_shape(narrow), _role_shape(broad))
        self.assertNotIn(b"PRIVATE KEY", canonical(self.values))


if __name__ == "__main__":
    unittest.main()
