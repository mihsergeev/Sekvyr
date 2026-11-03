"""Local second-Store guards; no live panel, Helm, Kubernetes or secret output."""

import base64
import copy
from contextlib import contextmanager
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from app_modes import require
from helm_lifecycle import canonical
from plain_installation import binding_identity, REVISION
import plain_secondary_store as secondary
import test_plain_installation as fixtures


class SecondaryGuards(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.PlainGuards()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.p = fixture.app
        self.primary_cr, self.primary_target, self.state = fixture.synchronized()
        self.original_binding, self.original_values = copy.deepcopy(self.p.binding), copy.deepcopy(self.p.values)
        self.events, self.sealed, self.reason = [], False, "PanelUnavailable"
        self.fail_upgrade, self.bad_head, self.replaced_uid = False, False, False
        self.no_fresh_transport, self.no_real_stop, self.fail_restore, self.ready_endpoint = False, False, False, False
        self.replace_panel, self.auto_unseal = False, False
        self.endpoint_shape = []
        self.panel_deployment = {"metadata": {"uid": "synthetic-owned-panel", "generation": 1}, "spec": {
            "replicas": 1, "selector": {"matchLabels": {"app": "panel"}}}, "status": {
                "observedGeneration": 1, "replicas": 1, "readyReplicas": 1, "availableReplicas": 1}}
        self.captures = {name: {"status": {"boot_id": "synthetic-boot-" + name, "pod_uid": "synthetic-pod-" + name},
            "footprint": {"template": {"synthetic": name}, "replica_sets": ["synthetic-rs-" + name]}} for name in ("env-app", "volume-app")}
        def frozen(name, before, seconds):
            require(before == self.captures[name], "Synthetic app restarted")
        apps = SimpleNamespace(modes={}, capture=lambda name: copy.deepcopy(self.captures[name]), frozen=frozen)
        @contextmanager
        def sealed():
            self.events.append("seal")
            self.sealed = True
            try:
                yield
            finally:
                self.sealed = False
                self.events.append("unseal")
        self.provider = SimpleNamespace(sealed=sealed, prepare_plain=Mock(side_effect=AssertionError("Source must not be registered again")))
        self.cases = SimpleNamespace(installation=self.p, c=SimpleNamespace(cluster=self.p.cluster), provider=self.provider,
            apps=apps, env_name="env-app", volume_name="volume-app", agent_name="agent-app")
        def panel_get(kind, name):
            self.assertEqual(name, "panel")
            return copy.deepcopy(self.panel_deployment) if kind == "Deployment" else {"spec": {"selector": {"app": "panel"}}}
        def panel_scale(replicas):
            self.events.append("panel-up" if replicas else "panel-down")
            if replicas and self.fail_restore:
                raise RuntimeError("Synthetic panel restoration failed")
            if not replicas and self.no_real_stop:
                return
            self.panel_deployment["spec"]["replicas"] = replicas
            self.panel_deployment["metadata"]["generation"] += 1
            self.panel_deployment["status"] = {"observedGeneration": self.panel_deployment["metadata"]["generation"],
                "replicas": replicas, "readyReplicas": replicas, "availableReplicas": replicas}
            if not replicas and self.replace_panel:
                self.panel_deployment["metadata"]["uid"] = "foreign-replacement"
            if replicas and self.auto_unseal:
                self.sealed = False
        def panel_login():
            self.assertEqual(self.panel_deployment["spec"]["replicas"], 1)
            self.events.append("login-still-sealed" if self.sealed else "login-auto-unsealed")
        panel = SimpleNamespace(namespace="trial-panel", cluster=self.p.cluster, get=panel_get, scale=panel_scale,
            connect=lambda: self.events.append("reconnect"), login=panel_login,
            owner_request=lambda *args: (200, {"initialized": True, "sealed": self.sealed}))
        self.cases.c.panel = panel
        managed = {"manifest": {"metadata": {"uid": "own-managed"}}, "uid": "own-managed"}
        def upgrade(values):
            self.events.append("Helm")
            expected = copy.deepcopy(self.original_values)
            expected["installation"]["allowedTargetSecrets"].append(secondary.TARGET)
            self.assertEqual(values, expected)
            if self.fail_upgrade:
                raise RuntimeError("Synthetic pre-create interruption")
        self.p.lifecycle = SimpleNamespace(managed={"operator": managed}, upgrade=upgrade, _external_guard=lambda: None,
            _retained_guard=lambda: None, _get=lambda manifest: manifest, _owned=lambda current, uid: self.assertEqual(current["metadata"]["uid"], uid),
            _matches=lambda current, manifest: self.assertEqual(current, manifest))
        original_create, original_kube = self.p.cluster.create, self.p.cluster.kube
        def create(value):
            result = original_create(value)
            if value["kind"] == "SekvyrStore" and value["metadata"]["name"] == secondary.STORE:
                self.assertTrue(self.sealed)
                self.events.append("new-Store")
            if value["kind"] == "SekvyrSecret" and value["metadata"]["name"] == secondary.CR:
                self.assertTrue(self.sealed)
                self.events.append("new-CR")
                current = self.p.cluster.objects[("SekvyrSecret", secondary.CR)]
                store = self.p.cluster.objects[("SekvyrStore", secondary.STORE)]
                current["status"] = self.status(current, store, False)
            return result
        self.p.cluster.create = create
        def kube(*args, **kwargs):
            if args[:2] == ("get", "pods"):
                self.assertEqual(args[args.index("-n") + 1], "trial-panel")
                return SimpleNamespace(stdout=json.dumps({"items": [] if self.panel_deployment["spec"]["replicas"] == 0 else [{}]}))
            if args[:2] == ("get", "endpointslices"):
                self.assertEqual(args[args.index("-n") + 1], "trial-panel")
                return SimpleNamespace(stdout=json.dumps({"items": [{"endpoints": [{"conditions": {"ready": True}}]}] if self.ready_endpoint else [{"endpoints": self.endpoint_shape}]}))
            if args[:3] == ("get", "Secret", secondary.TARGET):
                target = self.p.cluster.objects.get(("Secret", secondary.TARGET))
                if args[args.index("-o") + 1] == "name":
                    return SimpleNamespace(stdout="secret/" + secondary.TARGET if target else "")
                self.assertIsNotNone(target)
                current = copy.deepcopy(target)
                if self.replaced_uid:
                    current["metadata"]["uid"] = str(uuid.uuid4())
                return SimpleNamespace(stdout=json.dumps(current))
            if args[0] == "patch":
                self.assertEqual(args[1], "SekvyrSecret")
                value = self.p.cluster.objects[(args[1], args[2])]
                operations = json.loads(args[args.index("-p") + 1])
                self.assertEqual([item["path"] for item in operations[:2]], ["/metadata/uid", "/metadata/resourceVersion"])
                if args[2] == self.p.cr_name:
                    value["status"].update(lastSuccessfulSyncTime="2026-11-02T01:00:03Z", lastAttemptTime="2026-11-02T01:00:03Z")
                else:
                    self.assertEqual(args[2], secondary.CR)
                    if self.sealed:
                        self.assertEqual(self.panel_deployment["spec"]["replicas"], 0)
                        self.events.append("transport-attempt")
                        value["status"]["lastAttemptTime"] = "2026-11-02T01:00:02Z" if self.no_fresh_transport else "2026-11-02T01:00:03Z"
                    else:
                        self.sync_secondary()
                return SimpleNamespace(stdout=json.dumps(value))
            return original_kube(*args, **kwargs)
        self.p.cluster.kube = kube
        self.clock = 0
        def monotonic():
            self.clock += 1
            return self.clock
        def wait(check):
            value = check()
            self.assertTrue(value, "Fake API did not reach the expected phase")
            return value
        self.enterContext(patch.object(secondary, "wait", side_effect=wait))
        self.enterContext(patch.object(secondary.time, "monotonic", side_effect=monotonic))
        self.enterContext(patch.object(secondary.time, "sleep"))

    def status(self, cr, store, current):
        generation = cr["metadata"]["generation"]
        result = {"observedGeneration": generation, "observedStoreUID": store["metadata"]["uid"], "observedStoreGeneration": store["metadata"]["generation"],
            "lastAttemptTime": "2026-11-02T01:00:04Z" if current else "2026-11-02T01:00:02Z",
            "conditions": [{"type": "DataCurrent", "status": "True" if current else "False", "reason": "Synchronized" if current else self.reason, "observedGeneration": generation},
                {"type": "BootstrapReady", "status": "True", "observedGeneration": generation},
                {"type": "WitnessReady", "status": "Unknown", "reason": "NotApplicablePlain", "observedGeneration": generation}]}
        if current:
            result.update(lastSuccessfulSyncTime=result["lastAttemptTime"], lastAppliedRevision="b" * 32)
        return result

    def sync_secondary(self):
        self.events.append("sync-new-target")
        p = self.p
        cr, store = p.cluster.objects[("SekvyrSecret", secondary.CR)], p.cluster.objects[("SekvyrStore", secondary.STORE)]
        uid = str(uuid.uuid4())
        p.cluster.objects[("Secret", secondary.TARGET)] = {"apiVersion": "v1", "kind": "Secret", "metadata": {
            "name": secondary.TARGET, "namespace": p.namespace, "uid": uid, "resourceVersion": "1", "annotations": {REVISION: "b" * 32}},
            "type": "Opaque", "data": copy.deepcopy(self.primary_target["data"])}
        binding = store["spec"]["bindings"][0]
        body = json.loads(base64.b64decode(self.state["data"]["state.json"]))
        body["bindings"][store["metadata"]["uid"] + "/" + binding["id"]] = {"mode": "Plain", "head": {} if self.bad_head else None,
            "crUID": cr["metadata"]["uid"], "crName": secondary.CR, "storeUID": store["metadata"]["uid"], "bindingID": binding["id"],
            "identity": binding_identity(binding), "targetName": secondary.TARGET, "targetUID": uid}
        self.state["data"]["state.json"] = base64.b64encode(canonical(body)).decode()
        self.state["metadata"]["resourceVersion"] = "2"
        cr["status"] = self.status(cr, store, True)

    def test_second_store_is_sealed_before_create_and_then_gets_owned_target(self):
        original_target = copy.deepcopy(self.primary_target)
        result = secondary.run(self.cases)
        self.assertTrue(result["sealedBeforeFirstTarget"])
        self.assertTrue(result["newTargetUIDFromProtectedState"])
        self.assertLess(self.events.index("seal"), self.events.index("new-Store"))
        self.assertLess(self.events.index("seal"), self.events.index("new-CR"))
        self.assertLess(self.events.index("unseal"), self.events.index("sync-new-target"))
        self.assertLess(self.events.index("panel-down"), self.events.index("transport-attempt"))
        self.assertLess(self.events.index("login-still-sealed"), self.events.index("unseal"))
        self.assertTrue(result["transportUnavailableBeforeFirstTarget"])
        self.assertEqual(self.primary_target, original_target)
        self.assertEqual(self.p.binding, self.original_binding)
        self.assertEqual(self.p.store_name, "plain-store")
        self.assertNotIn(("Secret", secondary.TARGET), self.p.owned.pins)
        self.provider.prepare_plain.assert_not_called()
        self.assertNotIn("dataDigest", json.dumps(result))

    def test_wrong_failure_reason_cannot_be_credited_as_panel_unavailable(self):
        self.reason = "StateInvalid"
        with self.assertRaisesRegex(RuntimeError, "sealed-panel unavailability"):
            secondary.run(self.cases)
        self.assertFalse(self.sealed)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())

    def test_missing_captured_lifecycle_never_adopts(self):
        self.p.lifecycle = None
        with self.assertRaisesRegex(RuntimeError, "original captured"):
            secondary.run(self.cases)
        self.assertFalse(self.events)

    def test_saved_plan_cannot_broaden_other_permissions(self):
        self.fail_upgrade = True
        with self.assertRaises(RuntimeError):
            secondary.run(self.cases)
        path = self.p.root / "secondary-store" / "plan.json"
        saved = json.loads(path.read_bytes())
        saved["store"]["spec"]["endpoint"]["url"] = "https://foreign.example.invalid"
        path.write_bytes(canonical(saved))
        self.fail_upgrade = False
        with self.assertRaisesRegex(RuntimeError, "exact reviewed context"):
            secondary.run(self.cases)
        self.assertNotIn("seal", self.events)

    def test_partial_created_outage_does_not_get_silently_replayed(self):
        self.reason = "SourceInvalid"
        with self.assertRaises(RuntimeError):
            secondary.run(self.cases)
        self.reason = "PanelUnavailable"
        with self.assertRaisesRegex(RuntimeError, "Partial secondary outage"):
            secondary.run(self.cases)
        self.assertEqual(self.events.count("seal"), 1)

    def test_forged_target_uid_or_non_plain_head_never_becomes_proof(self):
        self.bad_head = True
        with self.assertRaisesRegex(RuntimeError, "exact protected binding"):
            secondary.run(self.cases)
        self.assertFalse((self.p.root / "secondary-store" / "complete.json").exists())

    def test_replaced_runtime_target_uid_is_not_adopted(self):
        self.replaced_uid = True
        with self.assertRaisesRegex(RuntimeError, "UID, revision or data"):
            secondary.run(self.cases)
        self.assertFalse((self.p.root / "secondary-store" / "complete.json").exists())

    def test_invalid_bootstrap_cannot_be_credited_as_sealed_panel(self):
        original = self.status
        def invalid(cr, store, current):
            status = original(cr, store, current)
            if not current:
                status["conditions"][1]["status"] = "False"
            return status
        self.status = invalid
        with self.assertRaisesRegex(RuntimeError, "valid bootstrap"):
            secondary.run(self.cases)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())

    def test_transport_requires_a_fresh_attempt_after_real_panel_stop(self):
        self.no_fresh_transport = True
        with self.assertRaises(AssertionError):
            secondary.run(self.cases)
        self.assertEqual(self.panel_deployment["spec"]["replicas"], 1)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())

    def test_scale_request_without_stopped_panel_cannot_pass(self):
        self.no_real_stop = True
        with self.assertRaisesRegex(RuntimeError, "exact specification"):
            secondary.run(self.cases)
        self.assertEqual(self.panel_deployment["spec"]["replicas"], 1)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())

    def test_ready_panel_endpoint_blocks_transport_claim(self):
        self.ready_endpoint = True
        with self.assertRaises(AssertionError):
            secondary.run(self.cases)
        self.assertEqual(self.panel_deployment["spec"]["replicas"], 1)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())

    def test_null_endpoint_slice_is_only_an_empty_optional_slice(self):
        self.endpoint_shape = None
        secondary.run(self.cases)
        self.assertTrue((self.p.root / "secondary-store" / "complete.json").exists())

    def test_wrong_endpoint_shape_is_not_accepted_as_stopped_panel(self):
        for value in ({}, "", [None]):
            self.endpoint_shape = value
            self.panel_deployment["spec"]["replicas"] = 0
            with self.assertRaisesRegex(RuntimeError, "shape invalid"):
                secondary._panel_view(self.cases.c.panel, self.panel_deployment["metadata"]["uid"],
                    self.panel_deployment["spec"], 0)

    def test_failed_panel_restoration_never_becomes_outage_proof(self):
        self.fail_restore = True
        with self.assertRaisesRegex(RuntimeError, "restoration failed"):
            secondary.run(self.cases)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())
        self.assertFalse((self.p.root / "secondary-store" / "complete.json").exists())

    def test_replaced_panel_uid_is_never_scaled_as_an_adopted_replacement(self):
        self.replace_panel = True
        with self.assertRaisesRegex(RuntimeError, "restoration refused"):
            secondary.run(self.cases)
        self.assertNotIn("panel-up", self.events)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())

    def test_panel_must_still_be_sealed_after_restart_and_login(self):
        self.auto_unseal = True
        with self.assertRaisesRegex(RuntimeError, "vault remains sealed"):
            secondary.run(self.cases)
        self.assertFalse((self.p.root / "secondary-store" / "outage-proven.json").exists())

    def test_known_deleted_target_history_blocks_a_false_fresh_case(self):
        body = json.loads(base64.b64decode(self.state["data"]["state.json"]))
        body["bindings"]["synthetic-prior-record"] = {"targetName": secondary.TARGET}
        self.state["data"]["state.json"] = base64.b64encode(canonical(body)).decode()
        with self.assertRaisesRegex(RuntimeError, "protected creation history"):
            secondary.run(self.cases)
        self.assertFalse(self.events)


if __name__ == "__main__":
    unittest.main()
