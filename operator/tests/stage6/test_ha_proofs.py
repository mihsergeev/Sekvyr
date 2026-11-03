"""Prevent stale receipts and an unrelated early409 from satisfying HA proof."""

import copy
from concurrent.futures import Future
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dependency_cases import grant_hash
from ha_cases import correlated_hold, current_activation, require_pending, same_pod_replacement, lease_duration_patch


class HAProofGuards(unittest.TestCase):
    def test_expiry_injection_changes_only_duration_and_pins_holder_renewal_uid_rv(self):
        lease = {"metadata": {"uid": "public-lease", "resourceVersion": "42"},
            "spec": {"holderIdentity": "public-old-holder", "renewTime": "public-time", "leaseDurationSeconds": 15}}
        patch = lease_duration_patch(lease, 2, "public-old-holder")
        self.assertEqual([x for x in patch if x["op"] != "test"],
            [{"op": "replace", "path": "/spec/leaseDurationSeconds", "value": 2}])
        self.assertEqual(len(patch), 6)
        with self.assertRaises(RuntimeError):
            lease_duration_patch(lease, 2, "public-other-holder")
        lease["spec"].update(holderIdentity="public-new-holder", leaseDurationSeconds=2)
        restored = lease_duration_patch(lease, 15)
        self.assertEqual(restored[2]["value"], "public-new-holder")

    def test_same_pod_restart_requires_a_running_new_canonical_container_id(self):
        pod = {"metadata": {"uid": "public-pod"}, "status": {"containerStatuses": [{"name": "operator",
            "containerID": "containerd://" + "b" * 64, "state": {"running": {"startedAt": "public-time"}}}]}}
        self.assertTrue(same_pod_replacement(pod, "new-holder", "public-pod", "old-holder", "containerd://" + "a" * 64))
        for cid in (None, "", "containerd://new", "containerd://" + "a" * 64):
            wrong = copy.deepcopy(pod)
            wrong["status"]["containerStatuses"][0]["containerID"] = cid
            self.assertFalse(same_pod_replacement(wrong, "new-holder", "public-pod", "old-holder", "containerd://" + "a" * 64))
        pod["status"]["containerStatuses"][0]["state"] = {"waiting": {}}
        self.assertFalse(same_pod_replacement(pod, "new-holder", "public-pod", "old-holder", "containerd://" + "a" * 64))

    def state(self):
        body = {"format": "sekvyr-fence-grant-v1", "scope": {"view_id": "public-view"},
            "genesis_hash": "1" * 64, "installation_id": "public-installation", "bootstrap_generation": 2,
            "owner_pod_uid": "public-new-pod", "lease_holder_identity": "public-new-pod_process",
            "term": "2", "previous_grant_hash": "2" * 64, "authority_digest": "3" * 64,
            "snapshot": {"sequence": "9", "envelope_hash": "4" * 64}, "objects": [{"name": "state"}]}
        activation = {k: copy.deepcopy(v) for k, v in body.items() if k != "previous_grant_hash"}
        activation.update(format="sekvyr-fence-activation-v1", grant_hash=grant_hash({"body": body}))
        return {"scope": body["scope"], "genesis_hash": body["genesis_hash"], "authority_digest": body["authority_digest"],
            "snapshot": body["snapshot"], "enrollments": {"public-installation": {"bootstrap_generation": 2, "allowed_objects": body["objects"]}},
            "grants": {"public-installation": {"body": body}}, "activations": {"public-installation": {"body": activation}}}

    def test_current_full_context_required_even_when_hash_and_owner_look_valid(self):
        original = self.state()
        self.assertTrue(current_activation(original, "public-installation", "public-new-pod", "public-new-pod_process"))
        for field, value in (("lease_holder_identity", "old-process"), ("authority_digest", "5" * 64),
                             ("snapshot", {"sequence": "8"}), ("bootstrap_generation", 1), ("objects", [])):
            candidate = copy.deepcopy(original)
            candidate["grants"]["public-installation"]["body"][field] = value
            self.assertFalse(current_activation(candidate, "public-installation", "public-new-pod", "public-new-pod_process"), field)
        candidate = copy.deepcopy(original)
        candidate["activations"]["public-installation"]["body"]["lease_holder_identity"] = "historical-process"
        self.assertFalse(current_activation(candidate, "public-installation", "public-new-pod", "public-new-pod_process"))

    def test_held_record_must_match_unique_external_marker_and_exact_rv(self):
        expected = {"target_uid": "public-target", "old_pod_uid": "public-old-pod", "request_marker": "a" * 32, "resource_version": "42"}
        value = dict(expected, upstream_allowed=True, request_uid="public-request")
        self.assertTrue(correlated_hold(value, expected))
        for field in expected:
            changed = dict(value)
            changed[field] = "different"
            self.assertFalse(correlated_hold(changed, expected), field)
        self.assertFalse(correlated_hold(dict(value, request_uid=""), expected))

    def test_early_conflict_future_is_never_already_approved_late_write_evidence(self):
        pending = Future()
        require_pending(pending)
        pending.set_result(409)
        with self.assertRaises(RuntimeError):
            require_pending(pending)


if __name__ == "__main__":
    unittest.main()
