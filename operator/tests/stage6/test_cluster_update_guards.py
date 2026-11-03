"""Explicit webhook reauthorization must preserve scope and cleanup ancestry."""

import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cluster import Cluster
from fixture import canonical, write_private


def expression(namespace, secrets):
    return ('request.namespace == ' + json.dumps(namespace) +
        " && ((request.resource.group == '' && request.resource.resource == 'secrets' && request.name in " +
        json.dumps(secrets, separators=(",", ":")) +
        ") || (request.resource.group == 'apps' && request.resource.resource == 'deployments' && request.name in [\"app\"]))")


class ClusterUpdateGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.client = Cluster.__new__(Cluster)
        self.client.task = Path(self.directory.name)
        self.client.pins = self.client.task / "private" / "creation-uids"
        self.client.pins.mkdir(parents=True)
        self.client.fixture = {"namespaces": {"apps": "trial-apps"}}
        condition = [{"name": "exact-installation-and-managed-names", "expression": expression("trial-apps", ["state"])}]
        self.old = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "trial-fence", "uid": "creation-uid", "resourceVersion": "1"},
            "webhooks": [{"name": "trial.invalid", "failurePolicy": "Fail", "sideEffects": "None",
                "clientConfig": {"caBundle": "public-ca", "service": {"name": "stage6-fencer", "namespace": "trial-apps",
                    "path": "/admit", "port": 9443}}, "rules": [], "matchConditions": condition}]}
        self.pin = {"apiVersion": self.old["apiVersion"], "kind": self.old["kind"], "name": "trial-fence", "namespace": "",
            "uid": "creation-uid", "guardHash": self.client.guard_hash(self.old)}
        write_private(self.client.pins / "webhook.json", canonical(self.pin))
        for kind, name in (("Secret", "state"), ("Secret", "new-state"), ("Deployment", "app")):
            write_private(self.client.pins / (name + ".json"), canonical({"kind": kind, "name": name,
                "namespace": "trial-apps", "uid": name + "-uid"}))

    def test_reviewed_update_extends_guard_chain_and_preserves_creation_pin(self):
        candidate = copy.deepcopy(self.old)
        candidate["webhooks"][0]["matchConditions"][0]["expression"] = expression("trial-apps", ["state", "new-state"])
        updated = copy.deepcopy(candidate)
        updated["metadata"]["resourceVersion"] = "2"
        self.client.kube = Mock(side_effect=[SimpleNamespace(stdout=json.dumps(self.old)), SimpleNamespace(stdout=json.dumps(updated))])
        result = self.client.update_cluster_webhook(candidate)
        self.assertEqual(self.client.active_cluster_guard(self.pin), self.client.guard_hash(result))
        self.assertEqual(json.loads((self.client.pins / "webhook.json").read_text()), self.pin)
        patch = json.loads(self.client.kube.call_args.args[self.client.kube.call_args.args.index("-p") + 1])
        self.assertEqual(patch[:2], [{"op": "test", "path": "/metadata/uid", "value": "creation-uid"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "1"}])

    def test_scope_and_admission_guards_cannot_be_widened(self):
        for change in ("namespace", "unknown-object", "fail-open", "foreign-service", "foreign-union"):
            with self.subTest(change=change):
                candidate = copy.deepcopy(self.old)
                webhook = candidate["webhooks"][0]
                if change == "namespace":
                    webhook["matchConditions"][0]["expression"] = expression("foreign", ["state"])
                elif change == "unknown-object":
                    webhook["matchConditions"][0]["expression"] = expression("trial-apps", ["foreign-secret"])
                elif change == "fail-open":
                    webhook["failurePolicy"] = "Ignore"
                elif change == "foreign-union":
                    webhook["matchConditions"][0]["expression"] = "(" + expression("trial-apps", ["state"]) + ") || (" + expression("foreign", ["state"]) + ")"
                else:
                    webhook["clientConfig"]["service"]["namespace"] = "foreign"
                self.client.kube = Mock(return_value=SimpleNamespace(stdout=json.dumps(self.old)))
                with self.assertRaises(ValueError):
                    self.client.update_cluster_webhook(candidate)
                self.assertEqual(self.client.kube.call_count, 1)

    def test_historical_and_new_state_union_preserves_exact_namespace_scope(self):
        candidate = copy.deepcopy(self.old)
        old = expression("trial-apps", ["state"])
        new = expression("trial-apps", ["state", "new-state"])
        candidate["webhooks"][0]["matchConditions"][0]["expression"] = "(" + old + ") || (" + new + ")"
        updated = copy.deepcopy(candidate)
        updated["metadata"]["resourceVersion"] = "2"
        self.client.kube = Mock(side_effect=[SimpleNamespace(stdout=json.dumps(self.old)), SimpleNamespace(stdout=json.dumps(updated))])
        self.client.update_cluster_webhook(candidate)
        self.assertEqual(self.client.active_cluster_guard(self.pin), self.client.guard_hash(updated))

    def test_temporary_relay_and_exact_restore_keep_an_unambiguous_receipt_chain(self):
        relay = copy.deepcopy(self.old)
        relay["webhooks"][0]["clientConfig"]["service"]["name"] = "admission-relay"
        relay["metadata"]["resourceVersion"] = "2"
        restored = copy.deepcopy(self.old)
        restored["metadata"]["resourceVersion"] = "3"
        self.client.kube = Mock(side_effect=[SimpleNamespace(stdout=json.dumps(self.old)),
            SimpleNamespace(stdout=json.dumps(relay)), SimpleNamespace(stdout=json.dumps(relay)),
            SimpleNamespace(stdout=json.dumps(restored))])
        self.client.update_cluster_webhook(relay)
        self.client.update_cluster_webhook(restored)
        self.assertEqual(self.client.active_cluster_guard(self.pin), self.pin["guardHash"])
        self.assertEqual(len(list((self.client.task / "private" / "cluster-update-receipts").glob("*.json"))), 2)

    def test_live_structure_never_becomes_its_own_approval(self):
        changed = copy.deepcopy(self.old)
        changed["webhooks"][0]["failurePolicy"] = "Ignore"
        self.client.kube = Mock(return_value=SimpleNamespace(stdout=json.dumps(changed)))
        with self.assertRaises(RuntimeError):
            self.client.update_cluster_webhook(self.old)
        self.assertEqual(self.client.kube.call_count, 1)


if __name__ == "__main__":
    unittest.main()
