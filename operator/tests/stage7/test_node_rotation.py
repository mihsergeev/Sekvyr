"""Offline cryptographic and native-lifecycle guards, not actual rotation E2E."""

import copy
import base64
import hashlib
import json
import shutil
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from fixture import canonical, pem
from application import REVISION, RESOURCE, STORE, TARGET
from protocol import ProtocolAuthority, key_descriptor, signed
from rotation_cases import save_protocol_version
from node_rotation import NodeRotation, exact, successor_values, validate_authority, verify_key_revocation, resume_after_webhook_guard, resume_after_post_publish


class NodeGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sekvyr-stage6-")
        self.addCleanup(self.temp.cleanup)
        self.task = Path(self.temp.name).resolve()
        # The existing fixture validates its directory reservation as well as
        # source-produced crypto. No network or Kubernetes fixture is used.
        import fixture
        self.safe = fixture.safe_task
        from unittest.mock import patch
        self.patch = patch("fixture.safe_task", side_effect=lambda value: Path(value))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.protocol_patch = patch("protocol.safe_task", side_effect=lambda value: Path(value))
        self.protocol_patch.start()
        self.addCleanup(self.protocol_patch.stop)
        (self.task / "private").mkdir()
        (self.task / "private" / "fixture.json").write_bytes(canonical({"namespaces": {"panel": "trial-panel"}}))
        self.old = ProtocolAuthority(self.task)
        node = save_protocol_version(self.task / "node", self.old, "node")
        self.new = save_protocol_version(self.task / "read", node, "read")
        self.envelope, self.digest = self.new.snapshot(2, "a" * 64, "public-generation", "public-demo", action="rotate-read-key")
        self.wrapper = self.new.reader_wrap()
        self.job = NodeRotation.__new__(NodeRotation)
        self.job.root = self.task / "job"
        self.job.root.mkdir()
        self.job.original = self.old

    def test_real_new_node_and_aes_work_retired_material_cannot_decrypt(self):
        plaintext = verify_key_revocation(self.old, self.new, self.envelope, self.wrapper)
        self.assertEqual({value["name"] for value in plaintext["entries"]}, {"GENERATION", "DEMO_VALUE"})

    def test_role_rotation_or_scope_change_is_outside_narrow_node_case(self):
        for mutate in (lambda p: p.authority.__setitem__("witness_epoch", "2"),
                       lambda p: p.scope.__setitem__("project_id", "foreign"),
                       lambda p: p.authority.__setitem__("fencer_keys", [key_descriptor(ed25519.Ed25519PrivateKey.generate())])):
            new = copy.copy(self.new)
            new.authority, new.scope = copy.deepcopy(self.new.authority), copy.deepcopy(self.new.scope)
            mutate(new)
            with self.assertRaises(RuntimeError): validate_authority(self.old, new)

    def test_fake_revocation_without_replacing_both_keys_is_rejected(self):
        for field in ("node", "read_key"):
            new = copy.copy(self.new)
            setattr(new, field, getattr(self.old, field))
            with self.assertRaises(RuntimeError): verify_key_revocation(self.old, new, self.envelope, self.wrapper)

    def test_encrypted_wrapper_or_snapshot_tamper_is_not_a_successful_rotation(self):
        wrapper = copy.deepcopy(self.wrapper)
        wrapper["signature"] = "A" * len(wrapper["signature"])
        with self.assertRaises(InvalidSignature): verify_key_revocation(self.old, self.new, self.envelope, wrapper)

    def values(self):
        old = {"replicas": 0, "resources": {"limits": {"memory": "160Mi"}}, "rollout": {"enabled": True},
            "installation": {"bootstrapGeneration": 1, "identityKeySecret": {"name": "node-1", "uid": "node-uid"},
                "trustBundleSecret": {"name": "trust-1", "uid": "trust-uid"}, "stateSecret": {"name": "state-1", "uid": "state-uid"},
                "protectedSecretNames": [], "protectedSecretUIDs": [], "allowedTargetSecrets": ["target"]},
            "ha": {"enabled": True, "maintenance": True, "managedObjects": [{"name": "state-1"}, {"name": "target"}],
                "fencer": {"signingKeySecret": {"name": "signer-1"}, "tlsSecret": {"name": "reviewed-tls"}},
                "webhook": {"serviceName": "reviewed-service", "caBundle": "PUBLIC"}}}
        new = copy.deepcopy(old)
        new["replicas"] = 2
        new["installation"]["bootstrapGeneration"] = 2
        for key in ("identityKeySecret", "trustBundleSecret", "stateSecret"):
            new["installation"][key] = {"name": old["installation"][key]["name"] + "-new", "uid": old["installation"][key]["uid"] + "-new"}
        new["ha"]["managedObjects"][0] = {"name": "state-1-new"}
        new["ha"]["fencer"]["signingKeySecret"] = {"name": "signer-2"}
        return old, new, {"name": "state-1", "uid": "state-uid"}

    def test_next_values_preserve_resources_tls_and_all_previous_external_protection(self):
        old, new, pin = self.values()
        before = copy.deepcopy(old)
        actual = successor_values(old, new, pin)
        self.assertEqual(old, before)
        self.assertEqual(actual["replicas"], 0)
        self.assertEqual(actual["resources"], old["resources"])
        self.assertEqual(actual["ha"]["webhook"]["retiredStateSecrets"], [pin])
        self.assertEqual(actual["installation"]["protectedSecretNames"], ["node-1", "trust-1", "state-1"])
        self.assertEqual(actual["ha"]["fencer"]["tlsSecret"], old["ha"]["fencer"]["tlsSecret"])

    def test_previous_state_uid_or_unrelated_source_policy_cannot_be_rebased(self):
        old, new, pin = self.values()
        with self.assertRaises(RuntimeError): successor_values(old, new, {**pin, "uid": "replacement"})
        new["installation"]["allowedTargetSecrets"] = ["another-target"]
        with self.assertRaises(RuntimeError): successor_values(old, new, pin)

    def test_gateway_role_or_webhook_endpoint_change_is_not_node_rotation(self):
        for part in ("tlsSecret", "webhook"):
            old, new, pin = self.values()
            if part == "webhook": new["ha"]["webhook"]["serviceName"] = "foreign-service"
            else: new["ha"]["fencer"][part]["name"] = "other"
            with self.assertRaises(RuntimeError): successor_values(old, new, pin)

    def test_native_mutation_lost_result_does_not_reset_or_repeat_helm(self):
        lifecycle = SimpleNamespace(upgrade=Mock(side_effect=RuntimeError("synthetic interruption")))
        self.job.e = SimpleNamespace(lifecycle=lifecycle, register_managed=Mock())
        values = {"replicas": 0}
        with self.assertRaisesRegex(RuntimeError, "synthetic"): self.job._native_upgrade("stop", values)
        with self.assertRaisesRegex(RuntimeError, "coordinator review"): self.job._native_upgrade("stop", values)
        self.assertEqual(lifecycle.upgrade.call_count, 1)
        self.job.e.register_managed.assert_not_called()

    def test_native_success_does_not_replace_captured_lifecycle_or_reapply(self):
        lifecycle = SimpleNamespace(upgrade=Mock())
        self.job.e = SimpleNamespace(lifecycle=lifecycle, register_managed=Mock())
        self.job._native_upgrade("stop", {"replicas": 0})
        self.job._native_upgrade("stop", {"replicas": 0})
        self.assertIs(self.job.e.lifecycle, lifecycle)
        self.assertEqual(lifecycle.upgrade.call_count, 1)
        with self.assertRaises(RuntimeError): self.job._native_upgrade("stop", {"replicas": 2})

    def test_transition_lost_ack_resolves_exact_signed_slot_only(self):
        parent = {"cursor": {"journal_sequence": "2", "record_hash": "a" * 64}, "authority_digest": "b" * 64}
        transition = self.old.transition("rotate-read-key", parent, authority=self.new.authority, activating_envelope=self.envelope)
        snapshot = {"sequence": "2", "envelope_hash": self.digest}
        calls = []
        state = {"value": copy.deepcopy(parent)}
        def request(method, path, *args, **kwargs):
            calls.append((method, path))
            if method == "POST":
                state["value"] = {"cursor": {"journal_sequence": "3"}, "snapshot": snapshot, "authority": self.new.authority}
                raise RuntimeError("synthetic lost response")
            return 200, canonical({"kind": "transition", "transition": transition}), {}
        self.job.panel = SimpleNamespace(current=lambda: state["value"], witness_client=SimpleNamespace(request=request))
        self.assertEqual(self.job._transition(transition, snapshot)["snapshot"], snapshot)
        self.assertEqual(calls[1], ("GET", "/v2/logs/" + self.old.scope["log_id"] + "/records/3"))
        self.job._transition(transition, snapshot)
        self.assertEqual(sum(method == "POST" for method, path in calls), 1)

    def test_transition_conflicting_slot_never_claims_rotation_or_rebases(self):
        candidate = {"body": {"expected": {"journal_sequence": "2"}, "authority": self.new.authority}}
        request = Mock(return_value=(200, canonical({"kind": "transition", "transition": {"different": True}}), {}))
        self.job.panel = SimpleNamespace(current=lambda: {"cursor": {"journal_sequence": "7"}}, witness_client=SimpleNamespace(request=request))
        with self.assertRaisesRegex(RuntimeError, "no rebase"): self.job._transition(candidate, {})
        self.assertEqual(request.call_args.args[0], "GET")

    def test_private_candidate_is_immutable_on_resume(self):
        path = self.job.root / "candidate.json"
        exact(path, lambda: {"fixed": True})
        self.assertEqual(exact(path, lambda: {"fixed": False}), {"fixed": True})
        path.write_text('{"fixed": true}', encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "encoding"): exact(path, lambda: {})

    def drive(self, complete=True):
        """Run the orchestration, using real crypto and fake explicit providers."""
        import node_rotation as module
        old_values, new_values, state_pin = self.values()
        old_values["replicas"], old_values["ha"]["maintenance"] = 2, False
        old_values["ha"]["fencer"]["bootstrapSubjects"] = [{"username": "trial-admin", "uid": ""}]
        new_values["ha"]["fencer"]["bootstrapSubjects"] = copy.deepcopy(old_values["ha"]["fencer"]["bootstrapSubjects"])
        events = []
        current = {"cursor": {"journal_sequence": "2", "record_hash": "a" * 64}, "authority_digest": "b" * 64,
            "authority": copy.deepcopy(self.old.authority), "snapshot": {"sequence": "1", "envelope_hash": "c" * 64,
                "read_key_epoch": "1", "publisher_policy_epoch": "1"}}
        (self.task / "infrastructure-parameters.json").write_bytes(canonical({"node_name": "trial-node"}))
        (self.task / "private" / "panel-bootstrap.json").write_bytes(canonical({"machine_id": 1}))
        data = {"GENERATION": base64.b64encode(b"public-generation").decode(), "DEMO_VALUE": base64.b64encode(b"public-demo").decode()}
        state = {}
        def get(kind, name):
            if name == module.TARGET:
                return {"metadata": {"uid": "target-uid", "annotations": {module.REVISION: "opaque"}}, "data": data}
            if name == "state-1-new": return {"metadata": {"uid": "state-uid-new"}, "data": {"state.json": base64.b64encode(canonical(state)).decode()}}
            return {"metadata": {"uid": "state-uid"}}
        app = SimpleNamespace(generation=1, protocol=self.old, state_name="state-1", get=get, created={}, namespace="trial-apps",
            current=lambda *args: True, footprint=lambda: {"template": {}}, frozen=lambda before: True,
            status=lambda: {"pod_uid": "pod-uid", "boot_id": "boot"}, materials={"journal_ca": b"PUBLIC_CA"}, poke=lambda: None)
        def plan(value, **kwargs):
            self.assertEqual(kwargs, {"previous_generation": 1, "previous_state_uid": "state-uid", "allow_rollout": False})
            return {"body": {"cursor": value["cursor"], "allow_rollout": False, "recovery_id": "reviewed-recovery"}}
        app.recovery_plan = plan
        def recover(plan, env, wrap, installation):
            events.append("signed-recovery")
            self.assertEqual(events[-2], "native-bootstrap")
            state.update(bootstrapGeneration=2, nodeFingerprint=app.protocol.node_fingerprint,
                trustBundleUID=installation["trustBundleSecret"]["uid"], bindings={"binding": {"rollout": {"intent": {"eligible": False}}}},
                recovery={"id": plan["body"]["recovery_id"], "planHash": hashlib.sha256(canonical(plan)).hexdigest(),
                    "phase": "complete" if complete else "prepared"})
        panel = SimpleNamespace(protocol=self.old, private=self.task / "private", current=lambda: copy.deepcopy(current), recover=recover,
            request=lambda *args: (200, {"access_token": "synthetic-private-session"}),
            owner_request=lambda method, route, body, *args: (409, {"reason": "ContextMismatch"}) if route.endswith("/readers") else (201, {}))
        coordinator = SimpleNamespace(protocol=self.old, panel=panel, task=self.task, app=app, gateway_origin="https://journal.example.invalid",
            cluster=SimpleNamespace(kube=lambda *args: SimpleNamespace(stdout="synthetic-projected-token")))
        e = SimpleNamespace(installed=True, lifecycle=SimpleNamespace(managed={"explicit": True}, retained={}, external=[]), values=old_values,
            selected={"generation": "public-generation", "demo": "public-demo"}, c=coordinator, app=app, root=self.job.root,
            helm=self.task / "helm", chart=self.task / "chart", image="example.invalid/operator@sha256:" + "1" * 64)
        job = NodeRotation(e)
        def upgrade(label, value):
            events.append("native-" + label)
            self.assertEqual(value["replicas"], 2 if label == "resume" else 0)
            self.assertIs(value["ha"]["maintenance"], label != "resume")
            e.values = copy.deepcopy(value)
        job._native_upgrade = upgrade
        def transition(candidate, snapshot):
            current.update(snapshot=copy.deepcopy(snapshot), authority=copy.deepcopy(candidate["body"]["authority"]),
                cursor={"journal_sequence": str(int(current["cursor"]["journal_sequence"]) + 1), "record_hash": "d" * 64})
            return copy.deepcopy(current)
        job._transition = transition
        job._review_webhook = lambda values: [{"kind": "ConfigMap", "data": {"installation.json": json.dumps({"trustBundleSecret": {"uid": "trust-uid-new"}})}}]
        job._post_change = lambda: events.append("post-rotation-change")
        def prepare(generation, protocol, *args):
            app.generation, app.protocol, app.state_name = generation, protocol, "state-1-new"
            return {"bootstrap_generation": generation}
        preparation = SimpleNamespace(stop_operator=lambda: events.append("verified-zero-old-pods"), prepare=prepare)
        with patch.object(module, "Reconfiguration", return_value=preparation), patch.object(module, "next_trust_bundle", return_value={}),\
                patch.object(module, "reviewed_values", return_value=new_values), patch.object(module, "replicas_current", return_value=True):
            if complete:
                result = job.run()
                self.assertEqual(events, ["native-stop", "verified-zero-old-pods", "native-bootstrap", "signed-recovery", "native-resume", "post-rotation-change"])
                self.assertTrue(result["signedRecoveryWithoutHistoricalRollout"])
                self.assertEqual(e.values["ha"]["webhook"]["retiredStateSecrets"], [state_pin])
            else:
                with self.assertRaisesRegex(RuntimeError, "exact completion"): job.run()
                self.assertNotIn("native-resume", events)
                self.assertNotIn("post-rotation-change", events)

    def test_full_orchestration_native_stop_prepare_recover_resume_order(self):
        self.drive()

    def test_prepared_only_recovery_never_resumes_old_or_new_operator(self):
        self.drive(complete=False)

    def resume_fixture(self):
        previous, reviewed, old_state = self.values()
        values = successor_values(previous, reviewed, old_state)
        root, job = self.job.root, self.job
        shutil.copytree(self.task / "read", root / "new-read-key")
        snapshot = {"sequence": "2", "envelope_hash": self.digest, "read_key_epoch": "2", "publisher_policy_epoch": "1"}
        parent = {"snapshot": {"sequence": "1"}, "cursor": {"journal_sequence": "2"}, "authority_digest": "a" * 64}
        read = self.old.transition("rotate-read-key", parent, authority=self.new.authority, activating_envelope=self.envelope)
        enrollment = {"bootstrap_generation": 2}
        after = {"cursor": {"journal_sequence": "3"}, "authority": self.new.authority, "authority_digest": "b" * 64}
        candidate = self.new.transition("enroll-installation", after, enrollment=enrollment)
        new = copy.copy(self.new)
        new.authority = candidate["body"]["authority"]
        current = {"snapshot": snapshot, "cursor": {"journal_sequence": "4", "record_hash": "c" * 64},
            "authority": new.authority, "enrollments": {self.old.installation_id: enrollment}}
        baseline = {"oldState": old_state}
        trust = {"public": "reviewed"}
        data = {"node-1-new": {"node.pem": pem(new.node)}, "trust-1-new": {"trust.json": canonical(trust)},
            "signer-2": {"key.pem": pem(new.fencer)}, "state-1-new": {"installation.json": canonical({"installationID": new.installation_id, "bootstrapGeneration": 2})}}
        def get(kind, name):
            return {"type": "Opaque", "immutable": name != "state-1-new", "data": {key: base64.b64encode(raw).decode() for key, raw in data[name].items()}}
        app = SimpleNamespace(generation=2, node_secret_name="node-1-new", trust_name="trust-1-new", state_name="state-1-new",
            fencer_signer_secret_name="signer-2", get=get, enrollment=lambda: enrollment)
        manifest = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration", "metadata": {"name": "owned-fence"}, "webhooks": ["before"]}
        desired = copy.deepcopy(manifest)
        desired["webhooks"] = ["same-namespace-old-and-new-exact-names"]
        lifecycle = SimpleNamespace(managed={__import__("helm_lifecycle").identity(manifest): {"manifest": manifest, "uid": "webhook-uid"}},
            _external_guard=Mock(), _retained_guard=Mock(), render=lambda value: ([desired], None),
            _get=Mock(return_value={"metadata": {"uid": "webhook-uid"}}), _owned=Mock(), _matches=Mock())
        job.e, job.app = SimpleNamespace(values=previous, lifecycle=lifecycle), app
        job.panel = SimpleNamespace(current=lambda: copy.deepcopy(current))
        job._unchanged = Mock()
        progress = root / "prepared-progress.json"
        prepared_job = SimpleNamespace(app=app, expected_values=previous, plan={"phase": "prepared"}, plan_path=progress, _no_operator_pods=lambda: True)
        progress.write_bytes(canonical(prepared_job.plan))
        saved = {"self": job, "values": values, "current": current, "baseline": baseline, "new": new, "snapshot": snapshot,
            "envelope": self.envelope, "wrapper": self.wrapper, "previous": previous, "reviewed": reviewed,
            "candidate": candidate, "job": prepared_job, "old": self.old, "parent": parent}
        for name, value in {"run-started": {"baseline": baseline, "initial": {"snapshot": parent["snapshot"]}},
                "stop-intent": previous, "stop-done": {"nativeHelmUpgrade": True}, "read-transition": read,
                "enrollment": candidate, "activating-envelope": self.envelope, "new-reader-wrapper": self.wrapper,
                "next-trust": trust, "webhook-update-reviewed": {"uid": "webhook-uid", "before": manifest, "after": desired}}.items():
            (root / (name + ".json")).write_bytes(canonical(value))
        return saved, data

    def test_resume_only_exact_saved_phase_then_calls_shared_tail_without_new_transition(self):
        saved, data = self.resume_fixture()
        with patch.object(NodeRotation, "_finish_after_enrollment", return_value={"continued": True}) as finish:
            self.assertEqual(resume_after_webhook_guard(self.job, saved), {"continued": True})
        self.assertIs(finish.call_args.args[0], self.job)
        self.assertIs(finish.call_args.args[2], saved["current"])
        self.assertTrue((self.job.root / "webhook-guard-resume-started.json").exists())
        with self.assertRaisesRegex(RuntimeError, "already advanced"):
            resume_after_webhook_guard(self.job, saved)

    def test_resume_cursor_advance_requires_review_and_never_rebases(self):
        saved, data = self.resume_fixture()
        self.job.panel.current = lambda: {**saved["current"], "cursor": {"journal_sequence": "5"}}
        with patch.object(NodeRotation, "_finish_after_enrollment") as finish:
            with self.assertRaisesRegex(RuntimeError, "no rebase"): resume_after_webhook_guard(self.job, saved)
        finish.assert_not_called()

    def test_resume_recovered_state_or_replaced_material_denied_before_webhook(self):
        saved, data = self.resume_fixture()
        data["state-1-new"]["state.json"] = b'{"phase":"complete"}'
        with patch.object(NodeRotation, "_finish_after_enrollment") as finish:
            with self.assertRaisesRegex(RuntimeError, "state changed"): resume_after_webhook_guard(self.job, saved)
        finish.assert_not_called()

    def test_resume_different_retained_values_or_prepared_receipt_denied(self):
        saved, data = self.resume_fixture()
        saved["values"]["resources"]["limits"]["memory"] = "999Mi"
        with self.assertRaisesRegex(RuntimeError, "bootstrap-only delta"): resume_after_webhook_guard(self.job, saved)

    def test_resume_requires_original_frame_and_zero_old_operator_pods(self):
        saved, data = self.resume_fixture()
        with self.assertRaisesRegex(RuntimeError, "original"): resume_after_webhook_guard(self.job, {**saved, "self": object()})
        saved["job"]._no_operator_pods = lambda: False
        with self.assertRaisesRegex(RuntimeError, "old operator"): resume_after_webhook_guard(self.job, saved)

    def test_resume_changed_webhook_review_is_not_a_new_approval(self):
        saved, data = self.resume_fixture()
        path = self.job.root / "webhook-update-reviewed.json"
        review = json.loads(path.read_bytes())
        review["after"]["webhooks"] = ["foreign"]
        path.write_bytes(canonical(review))
        with self.assertRaisesRegex(RuntimeError, "prior webhook review"): resume_after_webhook_guard(self.job, saved)

    def post_fixture(self):
        job, root = self.job, self.job.root
        pair = {"generation": "post-node-generation", "demo": "post-node-demo"}
        before = {"deployment_uid": "same-app", "replica_sets": ["original-rs"], "template": {"metadata": {}}}
        old = {"generation": "public-generation", "pod_uid": "old-pod", "boot_id": "old-boot", "value_digest": "old-digest"}
        baseline = {"footprint": before, "status": old, "targetUID": "target-uid", "revision": "a" * 32, "oldState": {"uid": "old-state-uid"}}
        recovered = {"sequence": "2", "envelope_hash": self.digest, "read_key_epoch": "2", "publisher_policy_epoch": "1"}
        snapshot = dict(recovered, sequence="3", envelope_hash="d" * 64)
        enrollment = {"bootstrap_generation": 2}
        candidate = self.new.transition("enroll-installation", {"cursor": {"journal_sequence": "3"}, "authority": self.new.authority,
            "authority_digest": "a" * 64}, enrollment=enrollment)
        protocol = copy.copy(self.new)
        protocol.authority = candidate["body"]["authority"]
        plan = signed("sekvyr-e2e2/checkpoint-recovery/v1", {"operation": "recover", "recovery_id": "signed-recovery-id", "bootstrap_generation": 2,
            "previous_bootstrap_generation": 1, "previous_state_secret_uid": "old-state-uid", "allow_rollout": False,
            "scope": protocol.scope, "genesis_hash": protocol.genesis_hash, "node_fingerprint": protocol.node_fingerprint, "snapshot": recovered}, protocol.admin)
        active = {"replicas": 2, "ha": {"maintenance": False}, "installation": {"bootstrapGeneration": 2,
            "stateSecret": {"uid": "new-state"}, "identityKeySecret": {"uid": "new-node"}, "trustBundleSecret": {"uid": "new-trust"}}}
        bootstrap = copy.deepcopy(active)
        bootstrap["replicas"], bootstrap["ha"]["maintenance"] = 0, True
        body = {"version": 1, "installationID": protocol.installation_id, "bootstrapGeneration": 2,
            "nodeFingerprint": protocol.node_fingerprint, "trustBundleUID": "new-trust",
            "recovery": {"id": "signed-recovery-id", "phase": "complete", "planHash": hashlib.sha256(canonical(plan)).hexdigest()},
            "bindings": {"store-uid/" + protocol.binding_id: {"targetUID": "target-uid", "crUID": "cr-uid", "head": {
                "Sequence": "3", "EnvelopeHash": "d" * 64, "ReadKeyEpoch": "2", "PublisherPolicyEpoch": "1"}}}}
        target = {"metadata": {"uid": "target-uid", "annotations": {REVISION: "b" * 32}}, "data": {
            "GENERATION": base64.b64encode(pair["generation"].encode()).decode(), "DEMO_VALUE": base64.b64encode(pair["demo"].encode()).decode()}}
        after = copy.deepcopy(before)
        after["replica_sets"].append("new-rs")
        after["template"]["metadata"]["annotations"] = {"secrets.sekvyr.ru/restart-target-uid": "b" * 32}
        def get(kind, name):
            if name == TARGET: return copy.deepcopy(target)
            if name == "state": return {"metadata": {"uid": "new-state"}, "data": {"state.json": base64.b64encode(canonical(body)).decode()}}
            return {"metadata": {"uid": {"node": "new-node", "trust": "new-trust", STORE: "store-uid", RESOURCE: "cr-uid"}[name]}}
        deployment = {"metadata": {"generation": 1}, "spec": {"replicas": 2}, "status": {"observedGeneration": 1,
            "replicas": 2, "updatedReplicas": 2, "readyReplicas": 2, "availableReplicas": 2}}
        app = SimpleNamespace(generation=2, state_name="state", node_secret_name="node", trust_name="trust", get=get,
            enrollment=lambda: enrollment, protocol=protocol, current=lambda *args: {"status": {"lastAppliedRevision": "b" * 32}},
            status=lambda: {"generation": pair["generation"], "pod_uid": "new-pod", "boot_id": "new-boot", "value_digest": hashlib.sha256(pair["demo"].encode()).hexdigest()},
            footprint=lambda: copy.deepcopy(after))
        get_original = app.get
        app.get = lambda kind, name: copy.deepcopy(deployment) if kind == "Deployment" else get_original(kind, name)
        current = {"scope": protocol.scope, "genesis_hash": protocol.genesis_hash, "snapshot": snapshot, "authority": protocol.authority,
            "enrollments": {protocol.installation_id: enrollment}}
        lifecycle = SimpleNamespace(managed={"own-role": {"manifest": {"kind": "Role"}, "uid": "role-uid"}},
            _external_guard=Mock(), _retained_guard=Mock(), _get=Mock(return_value={}), _owned=Mock(), _matches=Mock())
        job.e = SimpleNamespace(root=self.task / "private", values=active, selected={"generation": "public-generation", "demo": "public-demo"}, lifecycle=lifecycle)
        job.app, job.c = app, SimpleNamespace(protocol=protocol, current=lambda: copy.deepcopy(current))
        for name, value in {"run-started": {"baseline": baseline}, "resume-intent": active, "resume-done": {"nativeHelmUpgrade": True},
                "bootstrap-intent": bootstrap, "bootstrap-done": {"nativeHelmUpgrade": True}, "enrollment": candidate,
                "recovery-plan": plan, "activating-envelope": self.envelope}.items():
            (root / (name + ".json")).write_bytes(canonical(value))
        (job.e.root / "after-node-rotation-values.json").write_bytes(canonical(pair))
        frame = {"self": job, "before": before, "old": old, "pair": pair, "snapshot": snapshot}
        return frame, body, current, after, target

    def test_already_published_completion_observes_only_and_saves_original_result(self):
        frame, state, current, after, target = self.post_fixture()
        self.job.c.publish = Mock(side_effect=AssertionError("Must never republish"))
        self.job._post_change = Mock(side_effect=AssertionError("Must never replay post change"))
        result = resume_after_post_publish(self.job, frame)
        self.assertTrue(result["signedRecoveryWithoutHistoricalRollout"])
        self.assertEqual(self.job.e.selected, frame["pair"])
        self.job.c.publish.assert_not_called()
        self.job._post_change.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "already recorded"): resume_after_post_publish(self.job, frame)

    def test_post_completion_rejects_changed_pre_publish_baseline(self):
        frame, state, current, after, target = self.post_fixture()
        frame["before"]["replica_sets"].append("historical-unexpected-rs")
        with self.assertRaisesRegex(RuntimeError, "no-historical"): resume_after_post_publish(self.job, frame)

    def test_post_completion_never_rebases_later_canonical_publish(self):
        frame, state, current, after, target = self.post_fixture()
        current["snapshot"] = dict(current["snapshot"], sequence="4")
        with self.assertRaisesRegex(RuntimeError, "no rebase"): resume_after_post_publish(self.job, frame)

    def test_post_completion_requires_persisted_signed_recovery_complete(self):
        frame, state, current, after, target = self.post_fixture()
        state["recovery"]["phase"] = "prepared"
        with self.assertRaisesRegex(RuntimeError, "completion was lost"): resume_after_post_publish(self.job, frame)

    def test_post_completion_extra_rs_or_unrelated_template_change_cannot_pass(self):
        frame, state, current, after, target = self.post_fixture()
        after["replica_sets"].append("another-new-rs")
        with self.assertRaisesRegex(RuntimeError, "one-ReplicaSet"): resume_after_post_publish(self.job, frame)

    def test_post_completion_needs_exact_saved_values_and_native_resume_receipts(self):
        frame, state, current, after, target = self.post_fixture()
        (self.job.root / "resume-done.json").unlink()
        with self.assertRaisesRegex(RuntimeError, "artifact missing"): resume_after_post_publish(self.job, frame)


if __name__ == "__main__":
    unittest.main()
