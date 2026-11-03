"""Read-only restoration needs durable provenance, never name/mtime discovery."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app_modes import resource
from helm_lifecycle import canonical, identity
from helm_restore import restore_captured
from test_helm_lifecycle import HelmCluster


class RestoreGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cluster = HelmCluster(self.root)
        self.helm, self.chart = self.root / "helm", self.root / "chart"
        self.helm.write_bytes(b"fixture-tool")
        self.chart.mkdir()
        (self.chart / "Chart.yaml").write_text("name: trial", encoding="utf-8")
        self.directory = self.root / "private" / "helm-lifecycle-trial"
        self.directory.mkdir()
        self.preflights = self.root / "private" / "helm-preflights"
        self.preflights.mkdir()
        self.external = self.cluster.create(dict(resource("ServiceAccount", "reader", "trial-apps"), automountServiceAccountToken=False))
        for path in self.cluster.pins.glob("*.json"):
            path.write_bytes(canonical(json.loads(path.read_bytes())))
        self.external_pins = [{"kind": "ServiceAccount", "name": "reader", "uid": self.external["metadata"]["uid"]}]
        self.role = resource("Role", "trial-role", "trial-apps", api="rbac.authorization.k8s.io/v1")
        self.role["rules"] = [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["owned-state"], "verbs": ["get"]}]
        self.old, self.new = self.config("old", "old-reference"), self.config("new", "new-reference")
        self.old_path = self.capture([self.role, self.old], "install", [self.role, self.old])
        self.new_path = self.capture([self.role, self.new], "upgrade", [self.new])
        self.values = {"installation": {"namespace": "trial-apps"}, "explicit": "reviewed-values"}
        self.values_path = self.directory / ("values-" + hashlib.sha256(canonical(self.values)).hexdigest() + ".json")
        self.values_path.write_bytes(canonical(self.values))
        for manifest in (self.role, self.old, self.new):
            live = copy.deepcopy(manifest)
            live["metadata"].update(uid=self.uid(manifest), resourceVersion="1")
            live["metadata"].setdefault("annotations", {}).update({"meta.helm.sh/release-name": "trial", "meta.helm.sh/release-namespace": "trial-apps"})
            live["metadata"].setdefault("labels", {})["app.kubernetes.io/managed-by"] = "Helm"
            self.cluster.objects[(live["kind"], live["metadata"]["name"])] = live

    def config(self, name, data):
        value = resource("ConfigMap", name, "trial-apps")
        value.update(immutable=True, data={"installation.json": data})
        value["metadata"]["annotations"] = {"helm.sh/resource-policy": "keep"}
        return value

    def uid(self, manifest):
        return "known-uid-" + manifest["metadata"]["name"]

    def capture(self, manifests, action, created):
        receipt = {"format": "sekvyr-stage7-helm-preflight-v1", "action": action, "namespace": "trial-apps", "namespaceUID": "namespace-own", "release": "trial",
            "renderHash": hashlib.sha256(canonical(manifests)).hexdigest(), "external": self.external_pins,
            "absent": [{"apiVersion": item["apiVersion"], "kind": item["kind"], "namespace": "trial-apps", "name": item["metadata"]["name"],
                "manifestHash": hashlib.sha256(canonical(item)).hexdigest()} for item in created]}
        digest = hashlib.sha256(canonical(receipt)).hexdigest()
        (self.preflights / (digest + ".json")).write_bytes(canonical(receipt))
        path = self.directory / ("captured-" + digest + ".json")
        path.write_bytes(canonical([{"manifest": value, "uid": self.uid(value), "data": value.get("data")} for value in manifests]))
        for manifest in created:
            pin = {"apiVersion": manifest["apiVersion"], "kind": manifest["kind"], "namespace": "trial-apps", "name": manifest["metadata"]["name"],
                "uid": self.uid(manifest), "provenance": "helm-post-create-read", "manifestHash": hashlib.sha256(canonical(manifest)).hexdigest(), "preflightHash": digest}
            (self.cluster.pins / (hashlib.sha256(canonical(pin)).hexdigest() + ".json")).write_bytes(canonical(pin))
        return path

    def restore(self, older=None, values=None, selected=None):
        with patch("helm_restore.HelmLifecycle.render", return_value=([self.role, self.new], self.values_path)):
            return restore_captured(self.cluster, self.helm, self.chart, "trial", "trial-apps", values or self.values,
                selected or self.new_path, [self.old_path] if older is None else older)

    def test_exact_selected_receipts_restore_managed_and_retained_readonly(self):
        before = copy.deepcopy(self.cluster.objects)
        helper = self.restore()
        self.assertEqual(set(helper.managed), {identity(self.role), identity(self.new)})
        self.assertEqual(set(helper.retained), {identity(self.old)})
        self.assertEqual(helper.external, self.external_pins)
        self.assertEqual(self.cluster.objects, before)
        self.assertTrue(all(args[0] == "get" or args[0] == "replace" and "--dry-run=server" in args for args, kwargs in self.cluster.calls))

    def test_known_historical_configuration_needs_explicit_older_capture(self):
        with self.assertRaisesRegex(RuntimeError, "explicitly selected"):
            self.restore(older=[])

    def test_mtime_or_arbitrary_latest_filename_never_selects_a_capture(self):
        latest = self.directory / "latest.json"
        latest.write_bytes(self.new_path.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "exact capture"):
            self.restore(selected=latest)

    def test_replaced_live_uid_or_foreign_release_is_not_adopted(self):
        current = self.cluster.objects[("ConfigMap", "new")]
        uid = current["metadata"]["uid"]
        current["metadata"]["uid"] = "foreign-replacement"
        with self.assertRaises(RuntimeError):
            self.restore()
        current["metadata"]["uid"] = uid
        current["metadata"]["annotations"]["meta.helm.sh/release-name"] = "foreign"
        with self.assertRaises(RuntimeError):
            self.restore()

    def test_expected_values_and_namespace_pin_are_exact(self):
        with self.assertRaises(RuntimeError):
            self.restore(values={"installation": {"namespace": "foreign"}})
        self.cluster.namespace_uid = "replacement"
        with self.assertRaises(RuntimeError):
            self.restore()

    def test_partial_capture_cannot_replace_the_reviewed_complete_render(self):
        records = json.loads(self.new_path.read_bytes())
        self.new_path.write_bytes(canonical(records[:-1]))
        with self.assertRaisesRegex(RuntimeError, "partial"):
            self.restore()

    def test_retained_data_mutation_is_not_hidden_by_current_release_success(self):
        self.cluster.objects[("ConfigMap", "old")]["data"]["installation.json"] = "changed"
        with self.assertRaisesRegex(RuntimeError, "normalized manifest"):
            self.restore()

    def test_missing_creation_receipt_cannot_be_rebuilt_from_current_name(self):
        for path in self.cluster.pins.glob("*.json"):
            record = json.loads(path.read_bytes())
            if record.get("name") == "new":
                path.unlink()
        with self.assertRaisesRegex(RuntimeError, "creation-pinned"):
            self.restore()


if __name__ == "__main__":
    unittest.main()
