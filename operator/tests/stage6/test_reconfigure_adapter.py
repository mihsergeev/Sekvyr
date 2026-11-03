"""Fake callback/transport tests. These are not live signed-recovery evidence."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from application import APP, REVISION, TARGET, Application
from fixture import TrialFixture, canonical, write_private
from protocol import ProtocolAuthority
from reconfigure_adapter import RecoveryAdapter, _saved
import test_application_guards as application_guards
import test_reconfigure as reconfigure_guards


class AdapterCluster(reconfigure_guards.RuntimeCluster):
    def kube(self, *args, data=None, check=True):
        if args[:2] == ("auth", "whoami"):
            return SimpleNamespace(stdout=json.dumps({"status": {"userInfo": {"username": "trial-bootstrap"}}}), returncode=0)
        return super().kube(*args, data=data, check=check)


class Witness:
    def __init__(self, panel):
        self.panel = panel
        self.records, self.posts, self.lose_ack = {}, 0, False

    def request(self, method, path, raw=None, headers=None, expected=(200,), **kwargs):
        if method == "GET":
            return 200, canonical(self.records[path.rsplit("/", 1)[-1]]), {}
        self.posts += 1
        transition = json.loads(raw)
        if transition["body"]["expected"] != self.panel.state["cursor"]:
            return 409, b"{}", {}
        sequence = str(int(self.panel.state["cursor"]["journal_sequence"]) + 1)
        record = {"kind": "transition", "transition": transition}
        self.records[sequence] = record
        self.panel.state["cursor"] = {"journal_sequence": sequence, "record_hash": hashlib.sha256(canonical(record)).hexdigest()}
        self.panel.state["authority"] = copy.deepcopy(transition["body"]["authority"])
        enrollment = transition["body"]["enrollment"]
        self.panel.state["enrollments"][enrollment["installation_id"]] = copy.deepcopy(enrollment)
        if self.lose_ack:
            self.lose_ack = False
            raise RuntimeError("Synthetic lost acknowledgement")
        return 200, b"{}", {}


class Panel:
    def __init__(self, app, state):
        self.app, self.protocol, self.state = app, app.protocol, copy.deepcopy(state)
        self.witness_client = Witness(self)
        self.recoveries, self.exports = 0, 0

    def current(self):
        return copy.deepcopy(self.state)

    def offline_export(self):
        self.exports += 1
        envelope, _ = self.protocol.snapshot(1, "0" * 64, "public-trial", "public-trial")
        return canonical(envelope), canonical(self.protocol.reader_wrap())

    def recover(self, plan, envelope, wrapper, installation):
        # The real provider invokes the Go verifier. This fake models only its
        # durable completion receipt to exercise adapter ordering/resume.
        self.recoveries += 1
        state = self.app.cluster.objects[("Secret", self.app.state_name)]
        restored = {"installationID": self.protocol.installation_id, "bootstrapGeneration": self.app.generation,
            "nodeFingerprint": self.protocol.node_fingerprint, "trustBundleUID": installation["trustBundleSecret"]["uid"],
            "recovery": {"id": plan["body"]["recovery_id"], "planHash": hashlib.sha256(canonical(plan)).hexdigest(), "phase": "complete"},
            "bindings": {"public-unit-binding": {"rollout": {"intent": {"eligible": False}}}}}
        state["data"]["state.json"] = base64.b64encode(canonical(restored)).decode()
        return {"checkpointRecoveryComplete": True}


@unittest.skipUnless(os.environ.get("HELM_BIN"), "Real Helm render required")
class RecoveryAdapterGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        fixture = TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)
        self.cluster = AdapterCluster(self.task, fixture)
        self.app = Application(self.cluster, self.protocol)
        materials, snapshot, enrollment = application_guards.ApplicationGuards.prepared(self)
        self.image, self.helm = "example/operator@sha256:" + "d" * 64, os.environ["HELM_BIN"]
        self.chart = HERE.parents[1] / "charts" / "sekvyr-operator"
        values = self.app.chart_values(self.image, {"username": "trial-bootstrap", "uid": ""},
            "https://journal.example.test", materials["journal_ca"])
        self.values_path = self.task / "private" / "active-values-normalized.json"
        write_private(self.values_path, canonical(values))
        self.app.install_chart(values, self.helm, self.chart)
        self.cluster.objects[("Deployment", APP)]["spec"]["replicas"] = 1
        self.cluster.objects[("Secret", TARGET)]["metadata"]["annotations"] = {REVISION: "a" * 32}
        self.app.status = Mock(return_value={"boot_id": "unit-boot", "pod_uid": "unit-pod"})
        self.app.current = Mock(return_value={"status": {"lastSuccessfulSyncTime": "new-public-unit-time"}})
        self.app.frozen = Mock(return_value=True)
        self.state = {"scope": self.protocol.scope, "genesis_hash": self.protocol.genesis_hash,
            "cursor": {"journal_sequence": "2", "record_hash": "b" * 64}, "snapshot": snapshot,
            "authority": self.protocol.authority, "authority_digest": "c" * 64,
            "enrollments": {self.protocol.installation_id: enrollment}}
        self.panel = Panel(self.app, self.state)
        self.coordinator = SimpleNamespace(app=self.app, panel=self.panel, cluster=self.cluster,
            protocol=self.protocol, gateway_origin="https://journal.example.test")

    def adapter(self):
        return RecoveryAdapter(self.coordinator, self.values_path, self.image, self.helm, self.chart)

    def test_missing_state_uses_saved_creation_uid_and_exact_one_enrollment(self):
        old_uid = self.app.created[("Secret", self.app.state_name)]["uid"]
        del self.cluster.objects[("Secret", self.app.state_name)]
        result = self.adapter()(self.protocol, self.state, 2)
        self.assertTrue(result["signedRecoveryComplete"])
        self.assertEqual(self.panel.witness_client.posts, 1)
        self.assertEqual(self.panel.recoveries, 1)
        plan = json.loads((self.task / "private" / "recovery-adapter-g2" / "plan.json").read_bytes())
        self.assertEqual(plan["body"]["previous_state_secret_uid"], old_uid)
        self.assertFalse(plan["body"]["allow_rollout"])
        self.assertEqual(self.app.generation, 2)

    def test_lost_enrollment_ack_resolves_exact_saved_slot_and_repeat_is_noop(self):
        self.panel.witness_client.lose_ack = True
        adapter = self.adapter()
        first = adapter(self.protocol, self.state, 2)
        second = self.adapter()(self.protocol, self.state, 2)
        self.assertEqual(first, second)
        self.assertEqual(self.panel.witness_client.posts, 1)
        self.assertEqual((self.panel.recoveries, self.panel.exports), (1, 1))
        pointer = json.loads((self.task / "private" / "recovery-adapter-active-values.json").read_bytes())
        self.assertEqual(pointer["generation"], 2)
        self.assertEqual(self.adapter().expected_values_path.name, "active-values-generation-2.json")

    def test_changed_callback_input_and_foreign_exact_slot_cannot_rebase(self):
        adapter = self.adapter()
        adapter(self.protocol, self.state, 2)
        changed = copy.deepcopy(self.state)
        changed["cursor"]["journal_sequence"] = "99"
        with self.assertRaisesRegex(RuntimeError, "input changed"):
            adapter(self.protocol, changed, 2)
        transition = json.loads((self.task / "private" / "recovery-adapter-g2" / "enrollment.json").read_bytes())
        sequence = str(int(transition["body"]["expected"]["journal_sequence"]) + 1)
        self.panel.witness_client.records[sequence] = {"kind": "transition", "transition": {"wrong": True}}
        posts = self.panel.witness_client.posts
        with self.assertRaisesRegex(RuntimeError, "no rebase"):
            adapter._enroll(self.protocol, transition, self.state)
        self.assertEqual(self.panel.witness_client.posts, posts)

    def test_missing_persisted_inputs_fail_closed_instead_of_writing_null(self):
        missing = self.task / "private" / "missing-input.json"
        with self.assertRaisesRegex(RuntimeError, "explicit review"):
            _saved(missing, lambda: None)
        self.assertFalse(missing.exists())

    def test_old_current_status_is_not_new_bootstrap_verification(self):
        adapter = self.adapter()
        stopped = {"lastSuccessfulSyncTime": "old-public-unit-time"}
        self.app.current.return_value = {"status": {"lastSuccessfulSyncTime": "old-public-unit-time"}}
        self.assertFalse(adapter._fresh_current(self.state["snapshot"], stopped))
        self.app.current.return_value = {"status": {"lastSuccessfulSyncTime": "new-public-unit-time"}}
        self.assertTrue(adapter._fresh_current(self.state["snapshot"], stopped))


if __name__ == "__main__":
    unittest.main()
