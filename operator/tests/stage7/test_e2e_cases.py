"""Source guards for the actual E2E2 driver; no cluster or native invocation."""

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
import e2e_cases as cases
from fixture import canonical


class E2E2Guards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        task = Path(self.temp.name).resolve()
        private = task / "private"
        private.mkdir()
        (private / "journal-ca.crt").write_bytes(b"PUBLIC_SYNTHETIC_CA")
        (task / "infrastructure-parameters.json").write_bytes(canonical({"node_name": "synthetic-node"}))
        self.events = []
        def get(kind, name):
            if kind == "Deployment":
                return {"metadata": {"generation": 2}, "spec": {"replicas": 2}, "status": {"observedGeneration": 2,
                    "replicas": 2, "updatedReplicas": 2, "readyReplicas": 2, "availableReplicas": 2}}
            return {"metadata": {"uid": "synthetic-" + name}}
        base = {"leaderElection": {"id": cases.LEASE}, "ha": {"fencer": {"serviceAccount": {"uid": "synthetic-" + cases.FENCER_SA}}},
            "installation": {"bootstrapGeneration": 1, "identityKeySecret": {"uid": "synthetic-node-key"}}}
        self.app = SimpleNamespace(namespace="trial-apps", created={}, get=get,
            chart_values=lambda *args: copy.deepcopy(base),
            recovery_plan=lambda current: {"body": {"allow_rollout": False, "cursor": current["cursor"]}},
            start_application_after_initialize=lambda: self.events.append("application-start"),
            current=lambda *args: True, status=lambda: {"generation": "public-generation", "value_digest": hashlib.sha256(b"public-demo").hexdigest()},
            footprint=lambda: {"replica_sets": ["synthetic-rs"], "template": {"metadata": {}}})
        current = {"cursor": {"journal_sequence": "1", "record_hash": "a" * 64},
            "snapshot": {"sequence": "1", "envelope_hash": "b" * 64}}
        self.c = SimpleNamespace(task=task, private=private, app=self.app, gateway_origin="https://journal.example.invalid",
            panel=SimpleNamespace(offline_export=lambda: (b'{"public":"ciphertext"}', b'{"public":"wrap"}')),
            cluster=SimpleNamespace(kube=lambda *args: SimpleNamespace(stdout=json.dumps({"status": {"userInfo": {"username": "synthetic-admin"}}}))),
            current=lambda: copy.deepcopy(current))
        self.case = cases.E2E2Cases(self.c, "example.invalid/operator@sha256:" + "1" * 64, task / "helm", task / "chart")
        self.case.proof = Mock(return_value={"sourceGuardsOnly": True})
        self.case.prepared = True
        self.case.initial_snapshot = current["snapshot"]
        self.case.selected = {"generation": "public-generation", "demo": "public-demo"}

    def test_reviewed_values_preserve_bootstrap_and_pin_all_existing_identities(self):
        values = cases.reviewed_values(self.app, "image", {}, "origin", b"public", "synthetic-node")
        self.assertEqual(values["serviceAccount"], {"create": False, "uid": "synthetic-" + cases.SA})
        self.assertFalse(values["leaderElection"]["create"])
        self.assertEqual(values["leaderElection"]["uid"], "synthetic-" + cases.LEASE)
        self.assertFalse(values["ha"]["fencer"]["serviceAccount"]["create"])
        self.assertEqual(values["installation"], {"bootstrapGeneration": 1, "identityKeySecret": {"uid": "synthetic-node-key"}})
        self.assertEqual(values["resources"]["limits"]["memory"], "128Mi")

    def test_mismatched_fencer_pin_rejected_before_any_native_call(self):
        self.app.chart_values = lambda *args: {"leaderElection": {}, "ha": {"fencer": {"serviceAccount": {"uid": "foreign"}}}}
        with self.assertRaisesRegex(RuntimeError, "account pin"):
            cases.reviewed_values(self.app, "image", {}, "origin", b"public", "node")
        self.assertFalse(self.events)

    def test_two_replicas_requires_current_status_for_both_deployments(self):
        self.assertTrue(cases.replicas_current(self.app))
        good = self.app.get
        def get(kind, name):
            value = good(kind, name)
            if name.endswith("-fencer"): value["status"]["observedGeneration"] = 1
            return value
        self.app.get = get
        self.assertFalse(cases.replicas_current(self.app))
        self.app.get = lambda *args: {"metadata": {"generation": 2}, "spec": {"replicas": 1}, "status": {}}
        with self.assertRaises(RuntimeError): cases.replicas_current(self.app)

    def initialize(self, native_error=None):
        owner = self
        class Lifecycle:
            def __init__(self, *args):
                self.managed = {}
                owner.events.append("lifecycle-constructed")
            def render(self, values):
                return [{"kind": "ConfigMap", "data": {"installation.json": json.dumps({"namespace": "trial-apps", "ha": {"trial": True}})}}], None
            def install(self, values): owner.events.append("helm-install")
        def native(panel, plan, envelope, wrap, installation):
            owner.events.append("native-recovery")
            owner.assertEqual(plan, json.loads((owner.case.root / "initialization-plan.json").read_bytes()))
            owner.assertEqual(envelope, (owner.case.root / "initialization-envelope.json").read_bytes())
            owner.assertEqual(wrap, (owner.case.root / "initialization-reader-wrap.json").read_bytes())
            owner.assertEqual(installation, json.loads((owner.case.root / "reviewed-installation.json").read_bytes()))
            if native_error: raise native_error
        with patch.object(cases, "HelmLifecycle", Lifecycle), patch("host_recovery.recover", side_effect=native):
            self.case.initialize()

    def test_exact_saved_inputs_native_before_app_start_and_helm_install(self):
        self.initialize()
        self.assertEqual(self.events, ["lifecycle-constructed", "native-recovery", "application-start"])
        self.case.install()
        self.assertEqual(self.events[-1], "helm-install")
        self.assertTrue(self.case.installed)

    def test_native_rejection_never_starts_app_or_installs_and_no_automatic_reset(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic-rejected"):
            self.initialize(RuntimeError("synthetic-rejected"))
        saved = (self.case.root / "initialization-plan.json").read_bytes()
        self.assertEqual(self.events, ["lifecycle-constructed", "native-recovery"])
        self.assertFalse(self.case.initialized)
        with self.assertRaisesRegex(RuntimeError, "exact prepared instance"):
            self.case.initialize()
        self.assertEqual((self.case.root / "initialization-plan.json").read_bytes(), saved)

    def test_no_install_change_or_uninstall_before_authorized_initialization(self):
        for operation in (self.case.install, self.case.changed, self.case.equal, self.case.upgrade, self.case.uninstall):
            with self.assertRaises(RuntimeError): operation()
        self.assertFalse(self.events)

    def test_preparation_cannot_adopt_an_existing_data_log(self):
        self.case.prepared = False
        self.c.protocol = SimpleNamespace(scope={"log_id": "public-log"}, genesis_hash="a" * 64)
        self.c.current = lambda: {"scope": {"log_id": "public-log"}, "genesis_hash": "a" * 64, "snapshot": {"sequence": "1"}}
        with self.assertRaisesRegex(RuntimeError, "empty data log"):
            self.case.prepare()
        self.assertFalse((self.case.root / "initial-envelope.json").exists())

    def test_managed_uid_collision_never_adopts_external_identity(self):
        self.app.created[("Role", "operator")] = {"uid": "old-own-uid"}
        self.case.lifecycle = SimpleNamespace(managed={"role": {"uid": "replacement-uid", "manifest": {"kind": "Role",
            "metadata": {"name": "operator", "namespace": "trial-apps"}}}})
        with self.assertRaisesRegex(RuntimeError, "collides"):
            self.case.register_managed()
        self.assertEqual(self.app.created[("Role", "operator")]["uid"], "old-own-uid")

    def test_uninstall_delegates_only_captured_lifecycle_and_is_one_shot(self):
        self.case.installed = True
        self.case.lifecycle = SimpleNamespace(uninstall=Mock())
        self.case.uninstall()
        self.case.lifecycle.uninstall.assert_called_once_with()
        with self.assertRaises(RuntimeError): self.case.uninstall()

    def equality_fixture(self):
        self.case.installed = True
        target = {"metadata": {"uid": "same-target", "annotations": {cases.REVISION: "a" * 32}}, "data": {"PUBLIC": "same-encoded-data"}}
        self.app.get = Mock(return_value=target)
        self.app.status = Mock(return_value={"pod_uid": "same-pod", "boot_id": "same-boot"})
        self.app.frozen = Mock()
        self.c.publish = Mock(return_value={"sequence": "2", "envelope_hash": "b" * 64})
        self.app.poke = Mock()
        return target

    def test_existing_equality_proof_refuses_before_publish_or_poke(self):
        self.equality_fixture()
        (self.case.root / "e2e2-equal-proof.json").write_bytes(b'{"status":"PASS"}')
        with self.assertRaisesRegex(RuntimeError, "before another publication"): self.case.equal()
        self.c.publish.assert_not_called()
        self.app.poke.assert_not_called()
        self.app.get.assert_not_called()

    def test_post_node_equality_has_separate_proof_and_same_plaintext_frozen_process(self):
        target = self.equality_fixture()
        original = b'{"original":"immutable-proof"}'
        (self.case.root / "e2e2-equal-proof.json").write_bytes(original)
        label = "e2e2-post-node-equal"
        del self.case.proof  # Use the real exclusive writer for the new label.
        with patch("builtins.print"):
            self.case.equal(label)
        self.c.publish.assert_called_once_with(self.case.selected["generation"], self.case.selected["demo"])
        self.app.frozen.assert_called_once_with(self.app.footprint())
        proof_path = self.case.root / (label + "-proof.json")
        proof = json.loads(proof_path.read_bytes())
        self.assertEqual(proof["id"], label)
        self.assertEqual(proof["status"], "PASS")
        self.assertTrue(proof["sameDataRevisionPodBootAndReplicaSets"])
        self.assertEqual((self.case.root / "e2e2-equal-proof.json").read_bytes(), original)
        self.assertEqual(self.app.get.call_count, 2)
        with self.assertRaisesRegex(RuntimeError, "before another publication"): self.case.equal(label)
        self.assertEqual(self.c.publish.call_count, 1)

    def test_arbitrary_equality_label_cannot_create_an_unreviewed_proof_or_publish(self):
        self.equality_fixture()
        for label in ("another-equal", "../outside", None):
            with self.assertRaisesRegex(RuntimeError, "Unreviewed"): self.case.equal(label)
        self.c.publish.assert_not_called()

    def upgrade_fixture(self, refresh=True):
        self.case.installed = True
        self.case.values = {"resources": {"limits": {"memory": "128Mi"}}}
        self.case.register_managed = Mock()
        self.app.namespace = "trial-apps"
        self.app.status = Mock(return_value={"pod_uid": "same-app-pod", "boot_id": "same-app-boot",
            "generation": "public-generation", "value_digest": "public-digest"})
        self.app.frozen = Mock()
        checkpoint = {"sequence": "5", "envelope_hash": "a" * 64}
        cr = {"metadata": {"uid": "own-cr", "generation": 2}, "spec": {"storeRef": {"name": cases.STORE, "uid": "own-store"}},
            "status": {"observedGeneration": 2, "observedStoreUID": "own-store", "observedStoreGeneration": 3,
                "lastVerifiedCheckpoint": {"sequence": "5", "envelopeHash": "a" * 64},
                "lastSuccessfulSyncTime": "2030-01-01T00:00:01Z", "lastAttemptTime": "2030-01-01T00:00:01Z",
                "conditions": [{"type": name, "status": "True", "observedGeneration": 2} for name in
                    ("Ready", "BootstrapReady", "WitnessReady", "DataCurrent", "RolloutReady")]}}
        store = {"metadata": {"uid": "own-store", "generation": 3}}
        target = {"metadata": {"uid": "same-target", "annotations": {cases.REVISION: "b" * 32}}, "data": {"PUBLIC": "same-data"}}
        deployment = {"metadata": {"generation": 1}, "spec": {"replicas": 2}, "status": {"observedGeneration": 1,
            "replicas": 2, "updatedReplicas": 2, "readyReplicas": 2, "availableReplicas": 2}}
        def get(kind, name):
            return copy.deepcopy(cr if kind == "SekvyrSecret" else store if kind == "SekvyrStore" else deployment if kind == "Deployment" else target)
        self.app.get = get
        self.app.current = Mock(return_value=True)  # Deliberately stale True cannot suffice.
        self.c.current = Mock(return_value={"snapshot": checkpoint, "authority": {"unchanged": True}, "enrollments": {"same": True}})
        self.c.publish = Mock(side_effect=AssertionError("Upgrade must not publish to force freshness"))
        def poke():
            if refresh:
                cr["status"]["lastSuccessfulSyncTime"] = cr["status"]["lastAttemptTime"] = "2030-01-01T00:00:03Z"
        self.app.poke = Mock(side_effect=poke)
        self.upgraded = False
        def render(values):
            return [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"namespace": self.app.namespace,
                "name": cases.RELEASE + "-" + role}, "spec": {"template": {"spec": {"containers": [{"name": role,
                    "resources": copy.deepcopy(values["resources"])}]}}}} for role in ("operator", "fencer")], Path("synthetic-values")
        self.render = render
        def managed(values):
            return {cases.identity(value): {"manifest": value, "uid": "same-" + value["metadata"]["name"]} for value in render(values)[0]}
        def upgrade(values):
            self.assertEqual(values["resources"]["limits"]["memory"], "160Mi")
            self.upgraded = True
            self.case.lifecycle.managed = managed(values)
        self.case.lifecycle = SimpleNamespace(upgrade=Mock(side_effect=upgrade), managed=managed(self.case.values), render=Mock(side_effect=render),
            _external_guard=Mock(), _retained_guard=Mock(), _get=Mock(return_value={}), _owned=Mock(), _matches=Mock())
        (self.case.root / "reviewed-values.json").write_bytes(canonical(self.case.values))
        def snapshot(case, component):
            return {"deploymentUID": "same-fencer" if component == "fencer" else "same-operator",
                "pods": [{"uid": ("new-" if self.upgraded else "old-") + component + "-" + suffix} for suffix in ("one", "two")]}
        def wait_now(check, **kwargs):
            value = check()
            if not value: raise AssertionError("Synthetic observer not satisfied")
            return value
        return snapshot, wait_now

    def test_memory_upgrade_waits_fresh_success_after_both_old_pairs_absent(self):
        snapshot, wait_now = self.upgrade_fixture()
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot) as observed,\
                patch.object(cases, "old_component_pods_absent", return_value=True) as absence, patch.object(cases, "wait", side_effect=wait_now),\
                patch.object(cases, "datetime") as clock:
            clock.now.return_value = datetime(2030, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
            self.case.upgrade()
        self.app.poke.assert_called_once()
        self.app.current.assert_not_called()
        self.c.publish.assert_not_called()
        self.assertEqual({call.args[1] for call in absence.call_args_list}, {"operator", "fencer"})
        self.assertTrue(self.case.proof.call_args.args[1]["oldFencerPodsPhysicallyAbsent"])
        self.assertTrue(self.case.proof.call_args.args[1]["freshPostUpgradeSync"])

    def test_stale_preupgrade_current_true_cannot_credit_memory_upgrade(self):
        snapshot, wait_now = self.upgrade_fixture(refresh=False)
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot), patch.object(cases, "old_component_pods_absent", return_value=True),\
                patch.object(cases, "wait", side_effect=wait_now), patch.object(cases, "datetime") as clock,\
                patch("fresh_helm_sync.time.monotonic", side_effect=[0, 241]):
            clock.now.return_value = datetime(2030, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
            with self.assertRaisesRegex(RuntimeError, "was not observed"): self.case.upgrade()
        self.case.proof.assert_not_called()
        self.c.publish.assert_not_called()

    def test_deleting_old_operator_still_present_blocks_cutover_and_poke(self):
        snapshot, wait_now = self.upgrade_fixture()
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot), patch.object(cases, "old_component_pods_absent", return_value=False),\
                patch.object(cases, "wait", side_effect=wait_now):
            with self.assertRaises(AssertionError): self.case.upgrade()
        self.app.poke.assert_not_called()
        self.case.proof.assert_not_called()

    def test_remaining_old_fencer_blocks_cutover_even_when_operators_gone(self):
        snapshot, wait_now = self.upgrade_fixture()
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot),\
                patch.object(cases, "old_component_pods_absent", side_effect=lambda e, component, uids: component == "operator"),\
                patch.object(cases, "wait", side_effect=wait_now):
            with self.assertRaises(AssertionError): self.case.upgrade()
        self.app.poke.assert_not_called()
        self.case.proof.assert_not_called()
        self.assertFalse((self.case.root / "e2e2-helm-upgrade-cutover.json").exists())

    def retained_upgrade(self, snapshot):
        frame = {"self": self.case, "values": copy.deepcopy(self.case.values), "context": self.c.current(),
            "target": self.app.get("Secret", cases.TARGET), "old": self.app.status(), "before": self.app.footprint(),
            "fencers": snapshot(self.case, "fencer"), "old_operators": [pod["uid"] for pod in snapshot(self.case, "operator")["pods"]],
            "expected_cr": self.app.get("SekvyrSecret", cases.RESOURCE), "expected_store": self.app.get("SekvyrStore", cases.STORE)}
        frame["values"]["resources"]["limits"]["memory"] = "160Mi"
        self.case.lifecycle.upgrade(frame["values"])
        self.case.values = frame["values"]
        self.case.lifecycle.upgrade.reset_mock()
        return frame

    def test_resume_exact_already_applied_upgrade_never_repeats_helm_or_publish(self):
        snapshot, wait_now = self.upgrade_fixture()
        frame = self.retained_upgrade(snapshot)
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot),\
                patch.object(cases, "old_component_pods_absent", return_value=True), patch.object(cases, "wait", side_effect=wait_now),\
                patch.object(cases, "datetime") as clock:
            clock.now.return_value = datetime(2030, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
            cases.resume_after_upgrade(self.case, frame)
        self.case.lifecycle.upgrade.assert_not_called()
        self.c.publish.assert_not_called()
        self.case.register_managed.assert_not_called()
        self.app.poke.assert_called_once()
        self.assertTrue(self.case.proof.call_args.args[1]["freshPostUpgradeSync"])
        receipt = json.loads((self.case.root / "e2e2-helm-upgrade-observer-resume.json").read_bytes())
        self.assertTrue(receipt["originalAttemptIncomplete"])
        self.assertFalse(receipt["repeatedHelmOrPublish"])
        cutover = json.loads((self.case.root / "e2e2-helm-upgrade-cutover.json").read_bytes())
        self.assertEqual(set(cutover["oldFencerPodUIDs"]), {"old-fencer-one", "old-fencer-two"})

    def test_resume_stale_true_after_both_pairs_replaced_never_claims_fresh_sync(self):
        snapshot, wait_now = self.upgrade_fixture(refresh=False)
        frame = self.retained_upgrade(snapshot)
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot),\
                patch.object(cases, "old_component_pods_absent", return_value=True), patch.object(cases, "wait", side_effect=wait_now),\
                patch.object(cases, "datetime") as clock, patch("fresh_helm_sync.time.monotonic", side_effect=[0, 241]):
            clock.now.return_value = datetime(2030, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
            with self.assertRaisesRegex(RuntimeError, "was not observed"):
                cases.resume_after_upgrade(self.case, frame)
        self.case.proof.assert_not_called()
        self.case.lifecycle.upgrade.assert_not_called()
        self.c.publish.assert_not_called()

    def test_resume_old_fencer_physically_remaining_cannot_create_cutover(self):
        snapshot, wait_now = self.upgrade_fixture()
        frame = self.retained_upgrade(snapshot)
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot),\
                patch.object(cases, "old_component_pods_absent", side_effect=lambda e, role, uids: role == "operator"),\
                patch.object(cases, "wait", side_effect=wait_now), self.assertRaises(AssertionError):
            cases.resume_after_upgrade(self.case, frame)
        self.assertFalse((self.case.root / "e2e2-helm-upgrade-cutover.json").exists())
        self.app.poke.assert_not_called()
        self.case.proof.assert_not_called()
        self.case.lifecycle.upgrade.assert_not_called()

    def test_resume_changed_values_and_unowned_native_poststate_fail_before_poke(self):
        snapshot, _ = self.upgrade_fixture()
        frame = self.retained_upgrade(snapshot)
        frame["values"]["unreviewed"] = True
        with self.assertRaisesRegex(RuntimeError, "values differ"):
            cases.resume_after_upgrade(self.case, frame)
        del frame["values"]["unreviewed"]
        self.case.lifecycle._owned.side_effect = RuntimeError("Native UID replaced")
        with self.assertRaisesRegex(RuntimeError, "UID replaced"):
            cases.resume_after_upgrade(self.case, frame)
        self.app.poke.assert_not_called()
        self.case.lifecycle.upgrade.assert_not_called()

    def test_memory_preflight_rejects_unrelated_fencer_template_delta_before_helm(self):
        snapshot, wait_now = self.upgrade_fixture()
        def changed(values):
            rendered, path = self.render(values)
            if values["resources"]["limits"]["memory"] == "160Mi":
                rendered[1]["spec"]["template"]["spec"]["containers"][0]["image"] = "unreviewed-image"
            return rendered, path
        self.case.lifecycle.render.side_effect = changed
        with patch.object(cases, "owned_component_snapshot", side_effect=snapshot), patch.object(cases, "wait", side_effect=wait_now),\
                self.assertRaisesRegex(RuntimeError, "beyond both component memory"):
            self.case.upgrade()
        self.case.lifecycle.upgrade.assert_not_called()
        self.c.publish.assert_not_called()

    def test_old_operator_absence_queries_all_physical_pods_including_deleting(self):
        self.app.namespace = "trial-apps"
        self.app.get = Mock()
        self.c.cluster.kube = Mock(return_value=SimpleNamespace(stdout=json.dumps({"items": [{"metadata": {"uid": "old-one", "deletionTimestamp": "present"}}]})))
        self.assertFalse(cases.old_component_pods_absent(self.case, "operator", ["old-one", "old-two"]))
        self.assertFalse(cases.old_component_pods_absent(self.case, "fencer", ["old-one", "old-two"]))
        self.assertNotIn("-l", self.c.cluster.kube.call_args.args)
        self.c.cluster.kube.return_value.stdout = '{"items":[{"metadata":{"uid":"new-one"}}]}'
        self.assertTrue(cases.old_component_pods_absent(self.case, "operator", ["old-one", "old-two"]))
        self.assertTrue(cases.old_component_pods_absent(self.case, "fencer", ["old-one", "old-two"]))

    def component_graph(self):
        self.app.namespace = "trial-apps"
        deployment = {"metadata": {"name": "stage6-fencer", "uid": "owned-fencer", "generation": 1},
            "spec": {"selector": {"matchLabels": {"component": "fencer"}}, "template": {"spec": {"serviceAccountName": "fencer-reader"}}}}
        sets = [{"metadata": {"namespace": "trial-apps", "name": "fencer-rs", "uid": "own-fencer-rs", "ownerReferences": [
            {"apiVersion": "apps/v1", "kind": "Deployment", "name": "stage6-fencer", "uid": "owned-fencer", "controller": True}]}}]
        pods = [{"metadata": {"namespace": "trial-apps", "name": "fencer-" + str(index), "uid": "fencer-pod-" + str(index), "ownerReferences": [
            {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "fencer-rs", "uid": "own-fencer-rs", "controller": True}]},
            "spec": {"serviceAccountName": "fencer-reader", "containers": [{"name": "fencer"}]}, "status": {"containerStatuses": [
                {"name": "fencer", "ready": True, "state": {"running": {}}, "containerID": "containerd://" + str(index) * 64, "restartCount": 0}]}}
            for index in (1, 2)]
        self.app.get = Mock(return_value=deployment)
        self.c.cluster.kube = Mock(side_effect=lambda *args: SimpleNamespace(stdout=json.dumps({"items": sets if args[1] == "replicasets" else pods})))
        return deployment, sets, pods

    def test_component_guard_captures_full_expected_identity_and_detects_restart(self):
        deployment, sets, pods = self.component_graph()
        before = cases.owned_component_snapshot(self.case, "fencer")
        self.assertEqual(before["deploymentUID"], "owned-fencer")
        self.assertEqual(before["generation"], 1)
        self.assertEqual(before["replicaSets"], ["own-fencer-rs"])
        self.assertEqual({value["uid"] for value in before["pods"]}, {"fencer-pod-1", "fencer-pod-2"})
        pods[0]["status"]["containerStatuses"][0]["restartCount"] = 1
        self.assertNotEqual(cases.owned_component_snapshot(self.case, "fencer"), before)

    def test_component_graph_rejects_foreign_replica_set_or_pod_ownership(self):
        deployment, sets, pods = self.component_graph()
        sets[0]["metadata"]["ownerReferences"][0]["uid"] = "foreign-deployment"
        with self.assertRaisesRegex(RuntimeError, "foreign owner"): cases.owned_component_snapshot(self.case, "fencer")
        sets[0]["metadata"]["ownerReferences"][0]["uid"] = "owned-fencer"
        pods[0]["metadata"]["ownerReferences"][0]["uid"] = "foreign-rs"
        with self.assertRaisesRegex(RuntimeError, "foreign owner"): cases.owned_component_snapshot(self.case, "fencer")


if __name__ == "__main__":
    unittest.main()
