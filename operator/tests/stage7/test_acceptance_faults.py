"""Offline guards for two coordinator-invoked fault wrappers; no live evidence."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
import acceptance_faults as faults
from fixture import canonical
from protocol import ProtocolAuthority, domain
from rotation_cases import unwrap


def immediate(check, **kwargs):
    value = check()
    if not value:
        raise AssertionError("Synthetic predicate not satisfied")
    return value


class FaultGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        private = self.root / "private"
        private.mkdir()
        (private / "fixture.json").write_bytes(canonical({"namespaces": {"panel": "trial-panel"}}))
        with patch("protocol.safe_task", side_effect=lambda value: Path(value)):
            self.protocol = ProtocolAuthority(self.root)
        self.envelope, digest = self.protocol.snapshot(1, "0" * 64, "public-generation", "public-demo")
        self.snapshot = {"sequence": "1", "envelope_hash": digest, "read_key_epoch": "1", "publisher_policy_epoch": "1"}
        self.original = self.protocol.reader_wrap()
        self.wrapper = copy.deepcopy(self.original)
        self.enrollment = {"bootstrap_generation": 1}
        self.current = {"snapshot": self.snapshot, "authority": self.protocol.authority, "scope": self.protocol.scope,
            "genesis_hash": self.protocol.genesis_hash, "enrollments": {self.protocol.installation_id: self.enrollment}}
        self.reason, self.second, self.events = "CiphertextInvalid", 1, []
        self.cr = {"metadata": {"uid": "cr-uid", "generation": 1}, "status": {}}
        self.store = {"metadata": {"uid": "store-uid", "generation": 1}}
        self.target = {"metadata": {"uid": "target-uid", "annotations": {faults.REVISION: "a" * 32}}, "data": {"GENERATION": "public-encoded"}}
        self.app = SimpleNamespace(namespace="trial-apps", protocol=self.protocol, current=self.healthy, get=self.get,
            enrollment=lambda: self.enrollment, footprint=lambda: {"template": {}, "replica_sets": ["original-rs"]},
            status=lambda: {"pod_uid": "consumer-pod", "boot_id": "consumer-boot"}, frozen=Mock(), poke=self.poke)
        self.panel = SimpleNamespace(private=private, request=self.request, owner_request=self.owner)
        (private / "panel-bootstrap.json").write_bytes(canonical({"machine_id": 1}))
        cluster = SimpleNamespace(kube=lambda *args: SimpleNamespace(stdout="synthetic-private-token"))
        coordinator = SimpleNamespace(protocol=self.protocol, panel=self.panel, cluster=cluster, current=lambda: copy.deepcopy(self.current))
        self.case = SimpleNamespace(installed=True, lifecycle=SimpleNamespace(managed={"own-role": True}), app=self.app, c=coordinator, root=private)
        self.poke()

    def get(self, kind, name):
        return copy.deepcopy(self.target if kind == "Secret" else self.store if kind == "SekvyrStore" else self.cr)

    def healthy(self, snapshot, ready):
        return copy.deepcopy(self.cr) if self.cr["status"].get("conditions", [{}])[0].get("status") == "True" else False

    def poke(self):
        self.second += 1
        good = unwrap(self.protocol, self.wrapper, self.protocol.node) == self.protocol.read_key
        now = "2026-01-01T00:00:" + str(self.second).zfill(2) + "Z"
        self.cr["status"] = {"observedGeneration": 1, "observedStoreUID": "store-uid", "observedStoreGeneration": 1,
            "lastAttemptTime": now, "conditions": [{"type": "DataCurrent", "status": "True" if good else "False", "reason": "Current" if good else self.reason, "observedGeneration": 1},
                {"type": "BootstrapReady", "status": "True", "observedGeneration": 1}]}
        if good:
            self.cr["status"]["lastSuccessfulSyncTime"] = now

    def request(self, method, route, body=None, **kwargs):
        return (200, {"access_token": "synthetic-private-session"}) if method == "POST" else (200, copy.deepcopy(self.wrapper))

    def owner(self, method, route, body=None):
        if method == "GET": return 200, copy.deepcopy(self.envelope)
        self.wrapper = copy.deepcopy(body["wrapper"])
        self.events.append("restore" if self.wrapper == self.original else "wrong-key")
        return 200, {"has_wrap": True}

    def run_wrong(self):
        with patch.object(faults, "wait", side_effect=immediate):
            return faults.wrong_e2e_key(self.case)

    def test_real_signed_wrong_aes_fails_then_exact_wrapper_recovers_without_values_in_proof(self):
        result = self.run_wrong()
        self.assertEqual(self.events, ["wrong-key", "restore"])
        self.assertEqual(self.wrapper, self.original)
        self.assertTrue(result["wrongWrappedAESRejectedByRuntime"])
        for canary in ("public-generation", "public-demo", "synthetic-private", "ciphertext", "signature"):
            self.assertNotIn(canary, json.dumps(result))
        with self.assertRaisesRegex(RuntimeError, "no reset"): self.run_wrong()

    def test_wrong_failure_reason_never_credits_bad_key_and_restores_exact_original(self):
        self.reason = "StateInvalid"
        with self.assertRaises(AssertionError): self.run_wrong()
        self.assertEqual(self.events, ["wrong-key", "restore"])
        self.assertFalse((self.root / "private" / "wrong-e2e-key" / "complete.json").exists())

    def test_observer_failure_after_bad_key_still_restores_original_wrapper(self):
        self.app.frozen.side_effect = RuntimeError("synthetic observer failure")
        with self.assertRaisesRegex(RuntimeError, "observer"): self.run_wrong()
        self.assertEqual(self.wrapper, self.original)
        self.assertEqual(self.events, ["wrong-key", "restore"])

    def test_original_wrapper_or_canonical_hash_mismatch_prevents_fault_mutation(self):
        self.current["snapshot"]["envelope_hash"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "differs"): self.run_wrong()
        self.assertFalse(self.events)

    def test_fresh_failure_requires_exact_reason_generation_store_and_timestamp(self):
        self.wrapper = copy.copy(self.original)
        self.cr["status"]["conditions"][0].update(status="False", reason="CiphertextInvalid")
        previous = "2026-01-01T00:00:01Z"
        self.assertTrue(faults._failure(self.app, previous, "CiphertextInvalid"))
        self.cr["status"]["observedStoreUID"] = "replacement-store"
        self.assertFalse(faults._failure(self.app, previous, "CiphertextInvalid"))
        self.cr["status"]["observedStoreUID"] = "store-uid"
        self.cr["status"]["conditions"][0]["observedGeneration"] = 0
        self.assertFalse(faults._failure(self.app, previous, "CiphertextInvalid"))

    def pending(self):
        app = self.app
        app.generation, app.trust_name, app.state_name = 1, "trusted-pin", "state-pin"
        data = {"GENERATION": "new-data"}
        self.target["data"] = data
        intent = {"version": 1, "eligible": True, "revision": "a" * 32, "deployments": [{"name": faults.APP, "uid": "app-uid"}],
            "context": {"namespace": "trial-apps", "crName": faults.RESOURCE, "crUID": "cr-uid", "crGeneration": 1,
                "storeName": faults.STORE, "storeUID": "store-uid", "storeGeneration": 1, "bindingID": self.protocol.binding_id,
                "bootstrapGeneration": 1, "targetName": faults.TARGET, "targetUID": "target-uid"}}
        head = {"Sequence": "1", "EnvelopeHash": self.snapshot["envelope_hash"], "ReadKeyEpoch": "1", "PublisherPolicyEpoch": "1",
            "Scope": {name.title().replace("_Id", "ID"): value for name, value in self.protocol.scope.items()}, "WitnessEpoch": "1"}
        record = {"targetUID": "target-uid", "crUID": "cr-uid", "head": head, "rollout": {"intent": intent, "applied": [], "cancelled": False,
            "intentHash": hashlib.sha256(canonical(intent)).hexdigest()}}
        state = {"installationID": self.protocol.installation_id, "bootstrapGeneration": 1, "trustBundleUID": "trust-uid",
            "nodeFingerprint": self.protocol.node_fingerprint, "bindings": {"store-uid/" + self.protocol.binding_id: record}}
        self.target["metadata"]["annotations"][faults.INTENT] = json.dumps(intent)
        cr = copy.deepcopy(self.cr)
        cr["status"]["conditions"].append({"type": "RolloutReady", "status": "False", "reason": "DeploymentPaused"})
        app.current = lambda *args: cr
        previous = self.get
        app.get = lambda kind, name: {"metadata": {"uid": "app-uid"}, "spec": {"paused": True}} if kind == "Deployment" else {"metadata": {"uid": "trust-uid"}} if name == "trusted-pin" else {"data": {"state.json": base64.b64encode(canonical(state)).decode()}} if name == "state-pin" else previous(kind, name)
        return data, record

    def test_pending_requires_full_protected_context_before_any_term(self):
        data, record = self.pending()
        self.assertTrue(faults._pending(self.app, self.snapshot, data))
        record["rollout"]["intent"]["eligible"] = False
        with self.assertRaisesRegex(RuntimeError, "pending authorization"): faults._pending(self.app, self.snapshot, data)

    def test_public_marker_without_protected_pending_cannot_authorize_restart_test(self):
        data, record = self.pending()
        record["rollout"]["applied"] = [{"name": faults.APP, "uid": "app-uid"}]
        with self.assertRaisesRegex(RuntimeError, "pending authorization"): faults._pending(self.app, self.snapshot, data)

    def test_wrong_protected_head_cannot_be_credited_as_committed_new_secret(self):
        data, record = self.pending()
        record["head"]["EnvelopeHash"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "protected checkpoint"): faults._pending(self.app, self.snapshot, data)

    def test_debouncing_waits_for_paused_durable_proof_and_cannot_hide_invalid_intent(self):
        data, record = self.pending()
        current = self.app.current()
        rollout = current["status"]["conditions"][-1]
        rollout["reason"] = "Debouncing"
        self.assertFalse(faults._pending(self.app, self.snapshot, data))
        record["rollout"]["intent"]["eligible"] = False
        with self.assertRaisesRegex(RuntimeError, "pending authorization"):
            faults._pending(self.app, self.snapshot, data)
        record["rollout"]["intent"]["eligible"] = True
        rollout["reason"] = "DeploymentPaused"
        self.assertTrue(faults._pending(self.app, self.snapshot, data))

    def test_unknown_pending_reason_still_fails_hard(self):
        data, _ = self.pending()
        self.app.current()["status"]["conditions"][-1]["reason"] = "UnreviewedFailure"
        with self.assertRaisesRegex(RuntimeError, "explicitly paused"):
            faults._pending(self.app, self.snapshot, data)

    def restart_fixture(self):
        old = {"metadata": {"uid": "original-pod", "name": "own-operator"}}
        live = {"metadata": {"uid": "original-pod"}, "spec": {"serviceAccountName": faults.SA}, "status": {"containerStatuses": [
            {"name": "operator", "state": {"running": {}}, "containerID": "containerd://" + "2" * 64}]}}
        cluster = SimpleNamespace(kube=lambda *args: SimpleNamespace(stdout=json.dumps(live)))
        self.app.operator_pod = lambda: (old, "new-process-holder")
        return old, live, cluster

    def test_same_pod_new_container_and_new_holder_are_both_required(self):
        old, live, cluster = self.restart_fixture()
        self.assertTrue(faults._restarted(self.app, cluster, old, "old-holder", "containerd://" + "1" * 64))
        self.app.operator_pod = lambda: (old, "old-holder")
        self.assertFalse(faults._restarted(self.app, cluster, old, "old-holder", "containerd://" + "1" * 64))
        live["status"]["containerStatuses"][0]["containerID"] = "containerd://" + "1" * 64
        self.assertFalse(faults._restarted(self.app, cluster, old, "old-holder", "containerd://" + "1" * 64))

    def test_replaced_pod_is_not_credited_as_same_pod_process_restart(self):
        old, live, cluster = self.restart_fixture()
        live["metadata"]["uid"] = "another-pod"
        with self.assertRaisesRegex(RuntimeError, "replaced"): faults._restarted(self.app, cluster, old, "old-holder", "containerd://" + "1" * 64)

    def test_active_barriers_must_bind_new_holder_to_current_head_and_objects(self):
        pod = {"metadata": {"uid": "new-leader"}}
        objects = [{"name": "owned-target", "uid": "target-uid"}]
        body = {"format": "sekvyr-fence-grant-v1", "scope": self.protocol.scope, "genesis_hash": self.protocol.genesis_hash,
            "installation_id": self.protocol.installation_id, "bootstrap_generation": 1, "owner_pod_uid": "new-leader",
            "lease_holder_identity": "new-holder", "term": "2", "authority_digest": "a" * 64, "snapshot": self.snapshot, "objects": objects}
        activation = dict(body, format="sekvyr-fence-activation-v1", grant_hash=hashlib.sha256(domain("sekvyr-e2e2/fence-grant-hash/v1") + canonical(body)).hexdigest())
        state = {"snapshot": self.snapshot, "authority_digest": "a" * 64, "grants": {self.protocol.installation_id: {"body": body}},
            "activations": {self.protocol.installation_id: {"body": activation}}, "enrollments": {self.protocol.installation_id: {"bootstrap_generation": 1, "allowed_objects": objects}}}
        self.assertTrue(faults._active(state, self.protocol, pod, "new-holder"))
        state["snapshot"] = dict(self.snapshot, sequence="2")
        self.assertFalse(faults._active(state, self.protocol, pod, "new-holder"))

    def drive_leader(self, fail_pending=False, debounce_first=False, case_label="leader-pending-restart"):
        events, terminated = [], {"value": False}
        directory = self.root / case_label
        directory.mkdir()
        pair = {"generation": "new-generation", "demo": "new-demo"}
        data = {"GENERATION": base64.b64encode(pair["generation"].encode()).decode(), "DEMO_VALUE": base64.b64encode(pair["demo"].encode()).decode()}
        template = {"metadata": {}}
        baseline = {"targetUID": "target-uid", "revision": "a" * 32, "data": {"GENERATION": "old"},
            "footprint": {"template": copy.deepcopy(template), "replica_sets": ["old-rs"]}, "status": {"pod_uid": "old-app", "boot_id": "old-boot"}}
        deployment = {"metadata": {"uid": "owned-app"}, "spec": {"replicas": 1, "template": copy.deepcopy(template)}}
        target = {"metadata": {"uid": "target-uid", "annotations": {faults.REVISION: "b" * 32}}, "data": data}
        old = {"metadata": {"name": "operator-one", "uid": "operator-pod"}, "status": {"containerStatuses": [{"name": "operator", "containerID": "containerd://" + "1" * 64}]}}
        def get(kind, name): return copy.deepcopy(deployment if kind == "Deployment" else target)
        def change(kind, name, operations):
            for operation in operations:
                if operation["op"] == "test": self.assertEqual(operation["value"], deployment["spec"])
                elif operation["op"] == "remove": deployment["spec"].pop("paused")
                else: deployment["spec"]["paused"] = operation["value"]
            events.append("pause" if deployment["spec"].get("paused") else "unpause")
        def pending(*args):
            events.append("protected-pending")
            if fail_pending: return False
            if debounce_first and events.count("protected-pending") == 1:
                events.append("debouncing")
                return False
            return copy.deepcopy(target)
        def signal(value):
            self.assertEqual(value, "TERM")
            self.assertEqual(events[-1], "protected-pending")
            self.assertTrue(deployment["spec"]["paused"])
            terminated["value"] = True
            events.append("TERM")
        def published(*args):
            self.assertTrue(deployment["spec"]["paused"])
            events.append("publish")
            return self.snapshot
        final_template = copy.deepcopy(template)
        final_template["metadata"]["annotations"] = {"secrets.sekvyr.ru/restart-target-uid": "b" * 32}
        app = SimpleNamespace(get=get, patch=change, poke=lambda: None,
            operator_pod=lambda: (old, "old-holder"),
            current=lambda *args: True, status=lambda: {"generation": pair["generation"], "pod_uid": "new-app", "boot_id": "new-boot", "value_digest": hashlib.sha256(pair["demo"].encode()).hexdigest()},
            footprint=lambda: {"replica_sets": ["old-rs", "new-rs"], "template": final_template}, frozen=Mock())
        e = SimpleNamespace(app=app, c=SimpleNamespace(publish=published, cluster=object(), current=lambda: {}, protocol=self.protocol), pair=Mock(return_value=pair))
        process = Mock()
        process.prepare.return_value = process
        process.signal.side_effect = signal
        def poll(check, **kwargs):
            value = check()
            if not value and events[-1:] == ["debouncing"]:
                process.prepare.assert_not_called()
                process.signal.assert_not_called()
                value = check()
            if not value:
                raise AssertionError("Synthetic predicate not satisfied")
            return value
        with patch.object(faults, "_start", return_value=(directory, baseline)) as start, patch.object(faults, "wait", side_effect=poll),\
                patch.object(faults, "_pending", side_effect=pending), patch.object(faults, "_frozen"), patch.object(faults, "ProcessControl", return_value=process),\
                patch.object(faults, "_restarted", return_value=(old, "new-holder")), patch.object(faults, "_active", return_value=True), patch.object(faults, "replicas_current", return_value=True):
            if fail_pending:
                with self.assertRaises(AssertionError): faults.leader_pending_restart(e, case_label=case_label)
                process.signal.assert_not_called()
            else:
                result = faults.leader_pending_restart(e, case_label=case_label)
                self.assertTrue(result["leaderTerminatedAfterSecretAndProtectedPendingCommit"])
                self.assertTrue(terminated["value"])
                self.assertLess(events.index("publish"), events.index("protected-pending"))
                self.assertLess(events.index("protected-pending"), events.index("TERM"))
                self.assertLess(events.index("TERM"), events.index("unpause"))
            start.assert_called_once_with(e, case_label)
            e.pair.assert_called_once_with(case_label)
        self.assertNotIn("paused", deployment["spec"])

    def test_full_leader_flow_commits_pending_before_term_then_unpauses_once(self):
        self.drive_leader()

    def test_missing_committed_pending_never_terminates_leader_and_unpauses_finally(self):
        self.drive_leader(fail_pending=True)

    def test_debouncing_does_not_prepare_or_signal_until_next_pending_poll(self):
        self.drive_leader(debounce_first=True)

    def test_explicit_retry_label_uses_separate_candidate_and_preserves_original(self):
        original = self.root / "leader-pending-restart"
        original.mkdir()
        marker = original / "started.json"
        marker.write_bytes(b"PUBLIC original incomplete candidate and no TERM history")
        self.drive_leader(debounce_first=True, case_label="leader-pending-restart-after-debounce-fix")
        self.assertEqual(marker.read_bytes(), b"PUBLIC original incomplete candidate and no TERM history")
        self.assertFalse((original / "complete.json").exists())
        self.assertTrue((self.root / "leader-pending-restart-after-debounce-fix" / "complete.json").exists())

    def test_unknown_case_label_fails_before_start_pause_publish_or_helper(self):
        e = SimpleNamespace(pair=Mock(), c=SimpleNamespace(publish=Mock()), app=SimpleNamespace(patch=Mock()))
        with patch.object(faults, "_start") as start, patch.object(faults, "ProcessControl") as control:
            for label in ("other-leader", "../leader-pending-restart", None, 3):
                with self.subTest(label=label), self.assertRaisesRegex(RuntimeError, "Unreviewed"):
                    faults.leader_pending_restart(e, case_label=label)
        start.assert_not_called()
        control.assert_not_called()
        e.pair.assert_not_called()
        e.c.publish.assert_not_called()
        e.app.patch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
