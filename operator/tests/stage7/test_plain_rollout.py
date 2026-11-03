"""Local guards for explicit OFF -> ON; these are not live acceptance."""

import base64
import copy
import json
from types import SimpleNamespace
import unittest

from app_modes import resource
from helm_lifecycle import canonical
from plain_rollout import enable_rollout
import test_plain_installation as fixtures


class PlainRolloutGuards(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.PlainGuards()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.p = p = fixture.app
        self.cr, self.target, self.state = fixture.synchronized()
        self.calls = []
        self.after_upgrade = lambda: None
        self.fail_upgrade = False
        deployment = resource("Deployment", "plain-env", p.namespace, {
            "replicas": 1, "selector": {"matchLabels": {"app": "plain-env"}},
            "template": {"metadata": {"labels": {"app": "plain-env"}}, "spec": {
                "containers": [{"name": "app", "image": "example.invalid/public:fixture",
                    "envFrom": [{"secretRef": {"name": self.target["metadata"]["name"]}}]}]}}}, api="apps/v1")
        app = p.owned.create(deployment)
        self.sets = [{"metadata": {"uid": "synthetic-rs", "namespace": p.namespace,
            "ownerReferences": [{"kind": "Deployment", "uid": app["metadata"]["uid"], "controller": True}]}}]
        self.pods = [{"metadata": {"uid": "synthetic-pod", "namespace": p.namespace,
            "ownerReferences": [{"kind": "ReplicaSet", "uid": "synthetic-rs", "controller": True}]},
            "spec": {"containers": [{"name": "app"}]}, "status": {"containerStatuses": [{"name": "app",
                "containerID": "containerd://" + "a" * 64, "state": {"running": {"startedAt": "synthetic"}}}]}}]
        original = p.cluster.kube

        def kube(*args, **kwargs):
            if args[:2] in (("get", "replicasets"), ("get", "pods")):
                self.assertEqual(args[args.index("-n") + 1], p.namespace)
                values = self.sets if args[1] == "replicasets" else self.pods
                return SimpleNamespace(stdout=json.dumps({"items": copy.deepcopy(values)}))
            if args[0] != "patch":
                return original(*args, **kwargs)
            self.calls.append(args[1])
            value = p.cluster.objects[(args[1], args[2])]
            operations = json.loads(args[args.index("-p") + 1])
            self.assertEqual([op["path"] for op in operations[:2]], ["/metadata/uid", "/metadata/resourceVersion"])
            for op in operations:
                parent = value
                parts = op["path"].strip("/").split("/")
                for part in parts[:-1]:
                    parent = parent[part]
                if op["op"] == "test":
                    self.assertEqual(parent[parts[-1]], op["value"])
                else:
                    self.assertEqual(op["op"], "replace")
                    parent[parts[-1]] = copy.deepcopy(op["value"])
            value["metadata"]["resourceVersion"] = str(int(value["metadata"]["resourceVersion"]) + 1)
            value["metadata"]["generation"] += 1
            self.sync_status()
            return SimpleNamespace(stdout=json.dumps(value))

        p.cluster.kube = kube

        def upgrade(values):
            self.calls.append("Helm")
            self.assertEqual(values["rollout"], {"enabled": True, "allowedDeployments": ["plain-env"]})
            if self.fail_upgrade:
                raise RuntimeError("Synthetic interrupted Helm operation")
            self.after_upgrade()

        manifest = {"metadata": {"uid": "synthetic-managed"}}
        p.lifecycle = SimpleNamespace(managed={"operator": {"uid": "synthetic-managed", "manifest": manifest}},
            upgrade=upgrade, _external_guard=lambda: None, _retained_guard=lambda: None,
            _get=lambda value: copy.deepcopy(value), _owned=lambda value, uid: self.assertEqual(value["metadata"]["uid"], uid),
            _matches=lambda value, desired: self.assertEqual(value, desired))
        self.original_values = copy.deepcopy(p.values)
        self.original_binding = copy.deepcopy(p.binding)
        self.original_files = {path.name: path.read_bytes() for path in p.root.glob("*.json")}

    def sync_status(self):
        p = self.p
        store = p.cluster.objects[("SekvyrStore", p.store_name)]
        generation = self.cr["metadata"]["generation"]
        self.cr["status"].update(observedGeneration=generation, observedStoreGeneration=store["metadata"]["generation"],
            lastSuccessfulSyncTime="2026-11-02T01:00:01Z", lastAttemptTime="2026-11-02T01:00:01Z")
        self.cr["status"]["conditions"] = [dict(item, observedGeneration=generation) for item in self.cr["status"]["conditions"]]
        self.cr["status"]["conditions"].append({"type": "RolloutReady", "status": "True", "observedGeneration": generation})

    def record(self, update):
        body = json.loads(base64.b64decode(self.state["data"]["state.json"]))
        next(iter(body["bindings"].values())).update(update)
        self.state["data"]["state.json"] = base64.b64encode(canonical(body)).decode()

    def test_exact_upgrade_before_optin_and_idempotent_retry_no_restart(self):
        target, pods, sets = copy.deepcopy(self.target), copy.deepcopy(self.pods), copy.deepcopy(self.sets)
        result = enable_rollout(self.p, ["plain-env"])
        self.assertTrue(result["noHistoricalAppRestart"])
        self.assertEqual(self.calls, ["Helm", "SekvyrStore", "SekvyrSecret"])
        self.assertEqual(enable_rollout(self.p, ["plain-env"]), result)
        self.assertEqual(self.calls, ["Helm", "SekvyrStore", "SekvyrSecret"])
        self.assertEqual((self.target, self.pods, self.sets), (target, pods, sets))
        active = copy.deepcopy(self.p.values)
        active["rollout"] = self.original_values["rollout"]
        self.assertEqual(active, self.original_values)
        binding = copy.deepcopy(self.p.binding)
        binding["rollout"] = self.original_binding["rollout"]
        self.assertEqual(binding, self.original_binding)
        for name, raw in self.original_files.items():
            self.assertEqual((self.p.root / name).read_bytes(), raw)
        self.assertEqual(json.loads((self.p.root / "rollout-enable" / "reviewed-active-values.json").read_bytes()), self.p.values)

    def test_historical_eligible_intent_cannot_be_rearmed(self):
        self.record({"rollout": {"intent": {"eligible": True}}})
        with self.assertRaisesRegex(RuntimeError, "historical"):
            enable_rollout(self.p, ["plain-env"])
        self.assertFalse(self.calls)

    def test_replaced_store_uid_is_not_adopted_after_upgrade(self):
        def replace():
            self.p.cluster.objects[("SekvyrStore", self.p.store_name)]["metadata"]["uid"] = "synthetic-replacement"
        self.after_upgrade = replace
        with self.assertRaisesRegex(RuntimeError, "replaced"):
            enable_rollout(self.p, ["plain-env"])
        self.assertEqual(self.calls, ["Helm"])
        self.assertFalse(self.cr["spec"]["rollout"]["enabled"])

    def test_data_revision_or_process_change_cannot_claim_no_restart(self):
        self.after_upgrade = lambda: self.pods[0]["status"]["containerStatuses"][0].update(containerID="containerd://" + "b" * 64)
        with self.assertRaisesRegex(RuntimeError, "restarted"):
            enable_rollout(self.p, ["plain-env"])
        self.assertFalse((self.p.root / "rollout-enable" / "complete.json").exists())

    def test_saved_plan_cannot_change_source_even_on_interrupted_retry(self):
        self.fail_upgrade = True
        with self.assertRaisesRegex(RuntimeError, "Synthetic interrupted"):
            enable_rollout(self.p, ["plain-env"])
        path = self.p.root / "rollout-enable" / "plan.json"
        plan = json.loads(path.read_bytes())
        plan["new_cr"]["suspend"] = True
        path.write_bytes(canonical(plan))
        self.fail_upgrade = False
        with self.assertRaisesRegex(RuntimeError, "bootstrap or source"):
            enable_rollout(self.p, ["plain-env"])
        self.assertEqual(self.calls, ["Helm"])

    def test_incomplete_pod_observation_blocks_before_helm(self):
        self.pods.clear()
        with self.assertRaisesRegex(RuntimeError, "count is not stable"):
            enable_rollout(self.p, ["plain-env"])
        self.assertFalse(self.calls)

    def test_no_lifecycle_reconstruction_or_changed_resume_names(self):
        self.fail_upgrade = True
        with self.assertRaises(RuntimeError):
            enable_rollout(self.p, ["plain-env"])
        with self.assertRaisesRegex(RuntimeError, "retry changed"):
            enable_rollout(self.p, ["other-env"])
        self.p.lifecycle = None
        with self.assertRaisesRegex(RuntimeError, "original captured"):
            enable_rollout(self.p, ["plain-env"])


if __name__ == "__main__":
    unittest.main()
