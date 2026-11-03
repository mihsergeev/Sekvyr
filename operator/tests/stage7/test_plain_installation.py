"""Source guards for a pure Plain installation, never a live API acceptance."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app_modes import resource
from helm_lifecycle import HelmLifecycle
from plain_installation import PlainInstallation, REVISION, CHECKPOINT, binding_identity, canonical
from test_app_modes import FakeCluster, IMAGE


def public_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Public synthetic trial CA")])
    now = datetime.now(timezone.utc)
    return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(
        now - timedelta(days=1)).not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(
        key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


class PlainCluster(FakeCluster):
    config = Path("explicit-fixture-kubeconfig")

    def __init__(self, root):
        super().__init__(root)
        self.namespaces = {"trial-isolation"}
        self.fixture = {"namespaces": {"isolation": "trial-isolation", "apps": "trial-apps"}}
        (self.task / "private").mkdir()

    def namespace_pins(self):
        return {"trial-isolation": "namespace-own"}

    def create(self, value):
        result = super().create(value)
        key = result["kind"], result["metadata"]["name"]
        uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, ":".join(key)))
        result["metadata"]["uid"] = uid
        if result["kind"] in ("SekvyrStore", "SekvyrSecret", "Deployment"):
            result["metadata"]["generation"] = 1
        self.objects[key] = result
        for path in self.pins.glob("*.json"):
            pin = json.loads(path.read_bytes())
            if (pin["kind"], pin["name"]) == key:
                pin["uid"] = uid
                path.write_bytes(canonical(pin))
        return copy.deepcopy(result)


class Provider:
    def __init__(self):
        self.calls = []

    def prepare_plain(self, account, namespace):
        self.calls.append((account, namespace))
        return {"group": "", "project": "public-plain", "environment": "trial", "path": "/runtime",
            "source_config": {"SEKVYR_URL": "https://panel.example.invalid", "SEKVYR_PROJECT": "public-plain", "SEKVYR_ENV": "trial"}}


class PlainGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cluster = PlainCluster(self.temp.name)
        self.provider = Provider()
        self.chart = Path(__file__).resolve().parents[2] / "charts" / "sekvyr-operator"
        self.c = SimpleNamespace(cluster=self.cluster, panel_origin="https://panel.example.invalid",
            app=SimpleNamespace(materials={"panel_ca": public_ca()}))
        self.app = PlainInstallation(self.c, self.provider, IMAGE, os.environ.get("HELM_BIN", "unused-helm"), self.chart)

    def prepare(self):
        self.app.prepare()
        return self.app.prepare_store()

    def synchronized(self):
        self.prepare()
        store = self.app.owned.get("SekvyrStore", self.app.store_name)
        cr = self.cluster.objects[("SekvyrSecret", self.app.cr_name)]
        uid = str(uuid.uuid4())
        target = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": self.app.binding["target"]["name"], "namespace": self.app.namespace,
            "uid": uid, "resourceVersion": "5", "annotations": {REVISION: "a" * 32}}, "type": "Opaque", "data": {
                "GENERATION": base64.b64encode(b"one").decode(), "DEMO_VALUE": base64.b64encode(b"public-canary").decode()}}
        self.cluster.objects[("Secret", target["metadata"]["name"])] = target
        cr["status"] = {"observedGeneration": 1, "observedStoreUID": store["metadata"]["uid"], "observedStoreGeneration": 1,
            "lastAppliedRevision": "a" * 32, "lastSuccessfulSyncTime": "2026-11-02T01:00:00Z", "lastAttemptTime": "2026-11-02T01:00:00Z",
            "conditions": [{"type": "DataCurrent", "status": "True", "observedGeneration": 1},
                {"type": "WitnessReady", "status": "Unknown", "reason": "NotApplicablePlain", "observedGeneration": 1}]}
        state = self.cluster.objects[("Secret", self.app.state_name)]
        body = json.loads(base64.b64decode(state["data"]["state.json"]))
        binding = self.app.binding
        body["bindings"][store["metadata"]["uid"] + "/" + binding["id"]] = {
            "mode": "Plain", "head": None, "crUID": cr["metadata"]["uid"], "crName": self.app.cr_name,
            "storeUID": store["metadata"]["uid"], "bindingID": binding["id"], "identity": binding_identity(binding),
            "targetName": target["metadata"]["name"], "targetUID": uid}
        state["data"]["state.json"] = base64.b64encode(canonical(body)).decode()
        return cr, target, state

    def test_prepare_explicit_trust_pins_and_no_target_or_helm(self):
        with patch("plain_installation.HelmLifecycle") as helm:
            prepared = self.app.prepare()
        helm.assert_not_called()
        self.assertEqual(self.provider.calls, [("plain-operator", "trial-isolation")])
        trust = json.loads(base64.b64decode(self.cluster.objects[("Secret", self.app.trust_name)]["data"]["trust.json"]))
        self.assertEqual(trust["schemaVersion"], 1)
        self.assertEqual(trust["protocol"], "plain-v1")
        self.assertEqual(set(trust), {"schemaVersion", "protocol", "installationID", "bootstrapGeneration", "namespace", "serviceAccount", "panelOrigin", "nodePublicKeyFingerprint"})
        self.assertNotIn(("Secret", "plain-runtime-env"), self.cluster.objects)
        state = self.cluster.objects[("Secret", self.app.state_name)]
        self.assertFalse(state["immutable"])
        self.assertEqual(json.loads(base64.b64decode(state["data"]["state.json"]))["bindings"], {})
        self.assertEqual(len(prepared["externalRefs"]), 6)

    def test_exact_resume_does_not_regenerate_keys_or_create(self):
        self.prepare()
        original = self.app.node_pem, copy.deepcopy(self.cluster.objects)
        again = PlainInstallation(self.c, self.provider, IMAGE, self.app.helm, self.chart)
        again.prepare()
        again.prepare_store()
        self.assertEqual(again.node_pem, original[0])
        self.assertEqual(self.cluster.objects, original[1])
        with self.assertRaisesRegex(RuntimeError, "context changed"):
            PlainInstallation(self.c, self.provider, IMAGE.replace("1" * 64, "2" * 64), self.app.helm, self.chart)

    def test_scope_and_foreign_name_adoption_rejected(self):
        with self.assertRaises(RuntimeError):
            PlainInstallation(self.c, self.provider, IMAGE, self.app.helm, self.chart, namespace="trial-apps")
        self.cluster.objects[("ServiceAccount", self.app.sa)] = resource("ServiceAccount", self.app.sa, self.app.namespace)
        with self.assertRaises(RuntimeError):
            self.app.prepare()

    def test_crd_shape_plain_mode_target_allowlist_and_no_ha(self):
        prepared = self.prepare()
        binding, values = prepared["binding"], prepared["values"]
        self.assertEqual(binding["encryption"], {"mode": "Plain"})
        self.assertEqual(binding["source"]["pathPrefix"], "/runtime")
        self.assertNotIn("viewId", binding["source"])
        self.assertFalse(values["ha"]["enabled"])
        self.assertFalse(values["rollout"]["enabled"])
        self.assertFalse(values["serviceAccount"]["create"])
        self.assertFalse(values["leaderElection"]["create"])
        self.assertEqual(values["installation"]["allowedTargetSecrets"], ["plain-runtime-env"])
        with self.assertRaises(RuntimeError):
            self.app.prepare_store(target=self.app.state_name)

    def test_selection_shape_rejected_before_custom_resource_create(self):
        self.app.prepare()
        from jsonschema import ValidationError
        for selection in ({"mode": "NotARealMode"}, {"mode": "All", "unknown": "forbidden"},
                {"mode": "All", "keys": [{"path": "/runtime", "name": "GENERATION", "targetKey": "GENERATION"}]}):
            with self.assertRaises(ValidationError):
                self.app.prepare_store(selection=selection)
        self.assertNotIn(("SekvyrStore", self.app.store_name), self.cluster.objects)

    def test_target_ref_comes_from_protected_plain_record_not_get_adoption(self):
        _, target, _ = self.synchronized()
        reference = self.app.target_ref("one", "public-canary")
        self.assertEqual(reference, {"name": target["metadata"]["name"], "uid": target["metadata"]["uid"]})
        self.assertNotIn(("Secret", target["metadata"]["name"]), self.app.owned.pins)
        self.cluster.objects[("Secret", target["metadata"]["name"])]["metadata"]["uid"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "target UID"):
            self.app.target_ref()

    def test_stale_status_or_witness_claim_never_passes_plain_proof(self):
        cr, _, _ = self.synchronized()
        self.assertFalse(self.app.current(after_success="2026-11-02T01:00:00Z"))
        self.assertTrue(self.app.current(after_success="2026-11-02T00:59:59.999Z"))
        cr["status"]["observedStoreGeneration"] = 0
        self.assertFalse(self.app.current())
        cr["status"]["observedStoreGeneration"] = 1
        cr["status"]["lastVerifiedCheckpoint"] = {"sequence": "1", "envelopeHash": "b" * 64}
        with self.assertRaisesRegex(RuntimeError, "must not claim"):
            self.app.current()

    def test_plain_target_must_not_have_checkpoint_and_values_must_match(self):
        _, target, _ = self.synchronized()
        with self.assertRaisesRegex(RuntimeError, "expected generation"):
            self.app.target_ref(generation="two")
        target["metadata"]["annotations"][CHECKPOINT] = "forbidden"
        with self.assertRaisesRegex(RuntimeError, "target UID/revision/mode"):
            self.app.target_ref()

    def test_install_only_runs_when_explicit_and_with_exact_external_refs(self):
        self.prepare()
        with patch("plain_installation.HelmLifecycle") as helm:
            helm.return_value.install.return_value = {"helmSucceeded": True}
            self.assertEqual(self.app.install(), {"helmSucceeded": True})
            self.assertEqual(helm.call_args.args[-1], self.app.external_refs())
            self.assertEqual(helm.call_args.args[3:5], ("stage7-plain", "trial-isolation"))
            with self.assertRaises(RuntimeError):
                self.app.install()

    @unittest.skipUnless(os.environ.get("HELM_BIN"), "Exact Helm executable required")
    def test_real_plain_helm_render_has_runtime_pins_and_no_fencer(self):
        self.prepare()
        lifecycle = HelmLifecycle(self.cluster, os.environ["HELM_BIN"], self.chart, self.app.release,
            self.app.namespace, self.app.external_refs())
        rendered, _ = lifecycle.render(self.app.values, "1.37.0")
        self.assertFalse(any(value["kind"] in ("ServiceAccount", "Lease", "ValidatingWebhookConfiguration", "ClusterRole") for value in rendered))
        config_map = next(value for value in rendered if value["kind"] == "ConfigMap")
        config = json.loads(config_map["data"]["installation.json"])
        self.assertEqual(config["serviceAccountUID"], self.app.values["serviceAccount"]["uid"])
        self.assertEqual(config["leaderElectionLeaseName"], self.app.lease)
        self.assertEqual(config["leaderElectionLeaseUID"], self.app.values["leaderElection"]["uid"])
        self.assertNotIn("ha", config)
        self.assertEqual(config["allowedWitnessOrigins"], [])


if __name__ == "__main__":
    unittest.main()
