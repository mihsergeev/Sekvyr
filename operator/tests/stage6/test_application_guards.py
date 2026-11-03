"""Local mutation-scope tests. These do not claim real HA E2E acceptance."""

import base64
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from application import (API, APP, CHECKPOINT, FENCER_SA, LEASE, RESOURCE, RELOADER_OPTOUT,
    SA, STORE, TARGET, Application, application_manifest, binding_identity, write_values_once)
from fixture import TrialFixture, canonical
from protocol import ProtocolAuthority, key_descriptor, domain


class FakeCluster:
    def __init__(self, task, fixture):
        self.task, self.fixture = task, {"namespaces": fixture.namespaces}
        self.pins = task / "pins"
        self.pins.mkdir()
        self.uid = str(uuid.uuid4())
        self.objects, self.calls, self.created_manifests = {}, [], []

    def namespace_pins(self):
        return {self.fixture["namespaces"]["apps"]: self.uid}

    def kube(self, *args, data=None, check=True):
        self.calls.append((args, data))
        if args[:2] == ("get", "namespace"):
            value = {"metadata": {"uid": self.uid}}
        elif args[0] == "get":
            value = self.objects[(args[1], args[2])]
        elif args[0] == "patch":
            value = self.objects[(args[1], args[2])]
        else:
            raise AssertionError("Unexpected local test operation")
        return SimpleNamespace(stdout=json.dumps(copy.deepcopy(value)), returncode=0)

    def create(self, value):
        self.created_manifests.append(copy.deepcopy(value))
        value = copy.deepcopy(value)
        value["metadata"].update(uid=str(uuid.uuid4()), resourceVersion="7", generation=1)
        self.objects[(value["kind"], value["metadata"]["name"])] = value
        record = {"apiVersion": value["apiVersion"], "kind": value["kind"], "name": value["metadata"]["name"],
            "namespace": value["metadata"].get("namespace", ""), "uid": value["metadata"]["uid"]}
        if record["namespace"] == "" and record["kind"] != "Namespace":
            from cluster import Cluster
            record["guardHash"] = Cluster.guard_hash(value)
        (self.pins / (record["uid"] + ".json")).write_text(json.dumps(record), encoding="utf-8")
        return value

    def review_cluster_manifests(self, values):
        self.reviewed = copy.deepcopy(values)


class ApplicationGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        fixture = TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)
        self.cluster = FakeCluster(self.task, fixture)
        self.app = Application(self.cluster, self.protocol)

    def create_target(self):
        return self.app.secret(TARGET, {"GENERATION": b"public-trial"}, False)

    def test_private_values_retry_reuses_exact_bytes_and_refuses_changes(self):
        path = self.task / "private" / "values-retry.json"
        write_values_once(path, b'{"trial":true}')
        first = path.stat()
        write_values_once(path, b'{"trial":true}')
        self.assertEqual(path.stat().st_mtime_ns, first.st_mtime_ns)
        with self.assertRaisesRegex(RuntimeError, "overwrite refused"):
            write_values_once(path, b'{"trial":false}')
        self.assertEqual(path.read_bytes(), b'{"trial":true}')

    def prepared(self):
        ca = (self.task / "private" / "journal-ca.crt").read_bytes()
        cert = (self.task / "private" / "journal.crt").read_bytes()
        key = (self.task / "private" / "journal.key").read_bytes()
        materials = {name + "_ca": ca for name in ("panel", "witness", "journal", "fencer")}
        materials.update({name + "_cert": cert for name in ("fencer_tls", "operator_client", "fencer_client")})
        materials.update({name + "_key": key for name in ("fencer_tls", "operator_client", "fencer_client")})
        snapshot = {"sequence": "1", "envelope_hash": "a" * 64, "read_key_epoch": "1", "publisher_policy_epoch": "1"}
        enrollment = self.app.prepare("example/python@sha256:" + "1" * 64, "https://panel.example.test",
            "https://witness.example.test", snapshot, materials)
        return materials, snapshot, enrollment

    def test_namespace_replacement_and_foreign_create_block_before_mutation(self):
        self.cluster.uid = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "namespace replaced"):
            self.create_target()
        self.assertFalse(self.cluster.objects)
        self.cluster.uid = self.app.namespace_uid
        with self.assertRaisesRegex(RuntimeError, "outside owned namespace"):
            self.app.create({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": TARGET, "namespace": "foreign"}})
        self.assertFalse(self.cluster.objects)

    def test_patch_requires_creation_uid_and_prepends_current_rv_tests(self):
        target = self.create_target()
        self.app.patch("Secret", TARGET, [{"op": "add", "path": "/metadata/annotations", "value": {"trial": "safe"}}])
        args, _ = next((args, data) for args, data in reversed(self.cluster.calls) if args[0] == "patch")
        operations = json.loads(args[args.index("-p") + 1])
        self.assertEqual(operations[:2], [{"op": "test", "path": "/metadata/uid", "value": target["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "7"}])
        self.cluster.objects[("Secret", TARGET)]["metadata"]["uid"] = str(uuid.uuid4())
        before = len([call for call in self.cluster.calls if call[0][0] == "patch"])
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            self.app.patch("Secret", TARGET, [{"op": "add", "path": "/data/GENERATION", "value": "YQ=="}])
        self.assertEqual(len([call for call in self.cluster.calls if call[0][0] == "patch"]), before)

    def test_patch_cannot_replace_identity_or_move_data_from_identity(self):
        self.create_target()
        for operation in ({"op": "replace", "path": "/metadata", "value": {}},
                          {"op": "replace", "path": "/metadata/uid", "value": "foreign"},
                          {"op": "move", "from": "/metadata/uid", "path": "/data/uid"}):
            with self.subTest(operation=operation), self.assertRaisesRegex(RuntimeError, "Unsafe"):
                self.app.patch("Secret", TARGET, [operation])
        self.assertFalse(any(call[0][0] == "patch" for call in self.cluster.calls))

    def test_application_is_precreated_stopped_envfrom_and_reloader_optout(self):
        with self.assertRaises(ValueError):
            application_manifest(self.app.namespace, "example/python:latest")
        manifest = application_manifest(self.app.namespace, "example/python@sha256:" + "a" * 64)
        self.assertEqual(manifest["spec"]["replicas"], 0)
        self.assertEqual(manifest["metadata"]["annotations"], RELOADER_OPTOUT)
        spec = manifest["spec"]["template"]["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["containers"][0]["envFrom"], [{"secretRef": {"name": TARGET}}])
        self.assertNotIn("annotations", manifest["spec"]["template"]["metadata"])

    def test_bootstrap_enrollment_pins_full_precreated_object_set_and_private_values_not_in_chart(self):
        materials, _, enrollment = self.prepared()
        names = {(value["kind"], value["name"]) for value in enrollment["allowed_objects"]}
        self.assertEqual(names, {("Secret", TARGET), ("Secret", "operator-state"), ("Deployment", APP)})
        self.assertEqual(enrollment["namespace_uid"], self.app.namespace_uid)
        self.assertNotEqual(enrollment["operator_service_account_uid"], enrollment["fencer_service_account_uid"])
        self.assertEqual(self.app.get("Deployment", APP)["spec"]["replicas"], 0)
        values = self.app.chart_values("example/operator@sha256:" + "b" * 64,
            {"username": "trial-bootstrap", "uid": ""}, "https://journal.example.test", materials["journal_ca"])
        rendered = canonical(values)
        self.assertNotIn(b"PRIVATE KEY", rendered)
        for value in materials.values():
            if b"PRIVATE KEY" in value:
                self.assertNotIn(value, rendered)
        self.assertEqual(values["replicas"], 2)
        self.assertEqual(values["ha"]["fencer"]["replicas"], 2)
        self.assertIn("[redacted]", repr(self.app))

    def test_initialize_plan_signature_exact_cursor_and_no_implicit_rollout(self):
        _, snapshot, _ = self.prepared()
        current = {"cursor": {"journal_sequence": "2", "record_hash": "b" * 64}, "snapshot": snapshot}
        plan = self.app.recovery_plan(current)
        self.protocol.admin.public_key().verify(base64.urlsafe_b64decode(plan["signature"] + "=="),
            domain("sekvyr-e2e2/checkpoint-recovery/v1") + canonical(plan["body"]))
        self.assertEqual(plan["key_id"], key_descriptor(self.protocol.admin)["key_id"])
        self.assertEqual(plan["body"]["cursor"], current["cursor"])
        self.assertEqual(plan["body"]["snapshot"], snapshot)
        self.assertFalse(plan["body"]["allow_rollout"])
        self.assertEqual(plan["body"]["expected_state_sha256"], __import__("hashlib").sha256(b"").hexdigest())
        self.assertEqual(plan["body"]["binding"]["identity"], binding_identity(self.app.binding))
        with self.assertRaisesRegex(RuntimeError, "completed signed initialization"):
            self.app.start_application_after_initialize()

    def test_completion_wait_requires_exact_verified_cr_checkpoint(self):
        _, snapshot, _ = self.prepared()
        value = self.cluster.objects[("SekvyrSecret", RESOURCE)]
        value["status"] = {"observedGeneration": 1, "conditions": [{"type": "DataCurrent", "status": "True"}],
            "lastVerifiedCheckpoint": {"sequence": "0", "envelopeHash": "0" * 64}}
        self.assertFalse(self.app.current(snapshot))
        value["status"]["lastVerifiedCheckpoint"] = {"sequence": "1", "envelopeHash": snapshot["envelope_hash"]}
        self.assertTrue(self.app.current(snapshot))
        value["status"]["observedGeneration"] = 0
        self.assertFalse(self.app.current(snapshot))

    def test_generated_requests_match_actual_design_and_crd_schemas(self):
        import yaml
        from jsonschema import Draft7Validator, Draft202012Validator
        self.prepared()
        root = HERE.parents[1]
        design = json.loads((root / "design" / "resource.schema.json").read_text(encoding="utf-8"))
        crds = {value["spec"]["names"]["kind"]: value for path in (root / "charts" / "sekvyr-operator" / "crds").glob("*.yaml")
            for value in [yaml.safe_load(path.read_text(encoding="utf-8"))]}
        requests = [value for value in self.cluster.created_manifests if value["kind"] in ("SekvyrStore", "SekvyrSecret")]
        self.assertEqual({value["kind"] for value in requests}, {"SekvyrStore", "SekvyrSecret"})
        for resource in requests:
            with self.subTest(kind=resource["kind"]):
                schema = crds[resource["kind"]]["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
                for validator in (Draft202012Validator(design), Draft7Validator(schema)):
                    self.assertEqual(list(validator.iter_errors(resource)), [])
                    if resource["kind"] == "SekvyrStore":
                        wrong = copy.deepcopy(resource)
                        wrong["spec"]["bindings"][0]["encryption"]["freshness"]["mode"] = "StrictCurrent"
                        self.assertTrue(list(validator.iter_errors(wrong)), "Old helper typo must be rejected by both real schemas")

    def test_generated_trust_scope_names_and_source_prefix_match_encrypted_fixture(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        self.prepared()
        trust = json.loads(base64.b64decode(self.app.get("Secret", "operator-trust")["data"]["trust.json"]))
        view = trust["viewTrust"][0]
        self.assertEqual(set(view), {"trustKey", "storeUID", "bindingID", "realmID", "projectID", "environmentID",
            "viewID", "logID", "publisherPolicyEpoch", "publisherPublicKey", "publisherKeyFingerprint", "witness", "minimumCheckpoint"})
        for name in ("realm", "project", "environment", "view", "log"):
            self.assertEqual(view[name + "ID"], self.protocol.scope[name + "_id"])
        self.assertEqual(trust["nodePublicKeyFingerprint"], self.protocol.node_fingerprint)
        envelope, _ = self.protocol.snapshot(1, "0" * 64, "public-trial-generation", "public-trial-value")
        header, body = envelope["body"]["header"], envelope["body"]
        decode = lambda raw: base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=decode(header["snapshot_salt"]),
            info=domain("sekvyr-e2e2/snapshot-key/v1") + canonical(header)).derive(self.protocol.read_key)
        plaintext = json.loads(AESGCM(key).decrypt(decode(body["nonce"]), decode(body["ciphertext"]),
            domain("sekvyr-e2e2/snapshot-aad/v1") + canonical(header)))
        self.assertEqual({entry["path"] for entry in plaintext["entries"]}, {self.app.binding["source"]["pathPrefix"]})
        self.assertEqual({entry["name"] for entry in plaintext["entries"]}, {"GENERATION", "DEMO_VALUE"})

    def test_recovery_uses_new_state_and_trust_creation_uids_increased_generation(self):
        self.prepared()
        old_state = self.app.get("Secret", "operator-state")["metadata"]["uid"]
        old_trust = self.app.get("Secret", "operator-trust")["metadata"]["uid"]
        enrollment = self.app.prepare_recovery_reservations(2)
        self.assertEqual(enrollment["bootstrap_generation"], 2)
        self.assertNotEqual(enrollment["trust_bundle_secret_uid"], old_trust)
        self.assertNotIn(old_state, [ref["uid"] for ref in enrollment["allowed_objects"]])
        state = self.app.get("Secret", self.app.state_name)
        marker = json.loads(base64.b64decode(state["data"]["installation.json"]))
        self.assertEqual(marker["bootstrapGeneration"], 2)
        with self.assertRaisesRegex(RuntimeError, "must increase"):
            self.app.prepare_recovery_reservations(2)

    def test_context_atomic_resume_contains_only_pinned_refs_and_generation(self):
        self.prepared()
        self.app.prepare_recovery_reservations(2)
        loaded = Application(self.cluster, self.protocol)
        self.assertEqual((loaded.generation, loaded.state_name, loaded.trust_name), (2, "operator-state-r2", "operator-trust-r2"))
        context = (self.task / "private" / "application-context.json").read_bytes()
        self.assertNotIn(b"PRIVATE KEY", context)
        self.assertNotIn(b"read_key", context)
        changed = json.loads(context)
        changed["refs"]["node"]["uid"] = str(uuid.uuid4())
        (self.task / "private" / "application-context.json").write_text(json.dumps(changed))
        with self.assertRaisesRegex(RuntimeError, "creation UID"):
            Application(self.cluster, self.protocol)

    def test_fixture_tls_override_requires_exact_pinned_bytes_and_safe_label(self):
        materials, _, _ = self.prepared()
        name, label = "fencer-tls-repaired", "fencer-server-repaired"
        secret = self.app.secret(name, {"tls.crt": materials["fencer_tls_cert"], "tls.key": materials["fencer_tls_key"]})
        private = self.task / "private"
        (private / (label + ".crt")).write_bytes(materials["fencer_tls_cert"])
        (private / (label + ".key")).write_bytes(materials["fencer_tls_key"])
        override = {"fencerTLS": {"name": name, "uid": secret["metadata"]["uid"], "label": label}, "relayTLSLabel": "relay-repaired"}
        path = private / "fixture-overrides.json"
        path.write_text(json.dumps(override))
        loaded = Application(self.cluster, self.protocol)
        self.assertEqual(loaded.fencer_tls_secret_name, name)
        override["fencerTLS"]["label"] = "../foreign"
        path.write_text(json.dumps(override))
        with self.assertRaisesRegex(RuntimeError, "label invalid"):
            Application(self.cluster, self.protocol)

    def test_external_late_writer_keeps_old_rv_and_bearer_only_in_request_header(self):
        self.create_target()
        body = self.app.late_write_body("a" * 64)
        self.cluster.objects[("Secret", TARGET)]["metadata"]["resourceVersion"] = "8"
        ca = (self.task / "private" / "journal-ca.crt").read_bytes()
        self.cluster.config = self.task / "kubeconfig"
        self.cluster.config.write_text(json.dumps({"current-context": "trial", "contexts": [
            {"name": "trial", "context": {"cluster": "trial"}}], "clusters": [{"name": "trial", "cluster": {
                "server": "https://kubernetes.example.test:6443", "certificate-authority-data": base64.b64encode(ca).decode()}}]}))
        response = io.BytesIO(b"{\"reason\":\"Conflict\"}")
        response.status = 409
        token = "PRIVATE_EPHEMERAL_UNIT_MARKER"
        with patch("application.urllib.request.build_opener") as build:
            build.return_value.open.return_value = response
            self.assertEqual(self.app.token_update_target(token, body), 409)
            request = build.return_value.open.call_args.args[0]
            self.assertEqual(json.loads(request.data)["metadata"]["resourceVersion"], "7")
            self.assertEqual(request.get_header("Authorization"), "Bearer " + token)
            self.assertNotIn(token, request.full_url)
            self.assertEqual(request.full_url, "https://kubernetes.example.test:6443/api/v1/namespaces/" + self.app.namespace + "/secrets/" + TARGET)
        self.assertFalse(any(args[:2] == ("get", "Secret") for args, _ in self.cluster.calls[-1:]))
        with self.assertRaisesRegex(RuntimeError, "must conflict"):
            self.app.assert_late_write_conflicted(403)

    def test_external_write_cannot_escape_owned_uid_namespace_or_name(self):
        self.create_target()
        for field, value in (("namespace", "foreign"), ("name", "foreign"), ("uid", str(uuid.uuid4()))):
            body = self.app.late_write_body("b" * 64)
            body["metadata"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                self.app.token_update_target("public-unit-token", body)

    @unittest.skipUnless(os.environ.get("HELM_BIN"), "HELM_BIN required for real Helm rendering")
    def test_real_helm_render_uses_precreated_sa_lease_uid_without_adoption(self):
        materials, _, _ = self.prepared()
        values = self.app.chart_values("example/operator@sha256:" + "c" * 64,
            {"username": "trial-bootstrap", "uid": ""}, "https://journal.example.test", materials["journal_ca"])
        before = {key: self.app.get(*key)["metadata"]["uid"] for key in (("ServiceAccount", SA), ("ServiceAccount", FENCER_SA), ("Lease", LEASE))}
        chart = HERE.parents[1] / "charts" / "sekvyr-operator"
        result = self.app.install_chart(values, os.environ["HELM_BIN"], chart)
        self.assertEqual(result["operatorReplicas"], 2)
        for key, uid in before.items():
            self.assertEqual(self.app.get(*key)["metadata"]["uid"], uid)
        self.assertTrue(any(value["kind"] == "ValidatingWebhookConfiguration" for value in self.cluster.reviewed))
        operator = self.app.get("Deployment", "stage6-operator")
        self.assertEqual(operator["spec"]["replicas"], 2)


if __name__ == "__main__":
    unittest.main()
