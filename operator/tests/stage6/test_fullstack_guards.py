"""Refuse unsafe retries and replaced dependency identities in live harness."""

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import canonical, write_private
from fullstack import Coordinator
from cluster import Cluster


class FullstackGuards(unittest.TestCase):
    def test_separate_phase_cluster_approvals_preserve_old_crd_and_refuse_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            value = Cluster.__new__(Cluster)
            value.task = Path(directory)
            (value.task / "private").mkdir()
            crd = {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                "metadata": {"name": "examples.trial.invalid"}, "spec": {"scope": "Namespaced"}}
            role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": "trial-fencer"}, "rules": []}
            value.review_cluster_manifests([crd])
            value.review_cluster_manifests([role])
            value.review_cluster_manifests([role])
            self.assertEqual(len(value.reviewed_cluster_manifests()), 2)
            changed = dict(role, rules=[{"verbs": ["*"], "resources": ["*"]}])
            with self.assertRaises(ValueError):
                value.review_cluster_manifests([changed])
            self.assertEqual(len(list((value.task / "private").glob("cluster-allowlist*.json"))), 2)

    def test_partial_prepare_never_reinitializes_existing_reservations(self):
        with tempfile.TemporaryDirectory() as directory:
            value = Coordinator.__new__(Coordinator)
            value.private = Path(directory)
            write_private(value.private / "application-initial-envelope.json", b"{}")
            value.install_crds = Mock()
            with self.assertRaises(RuntimeError):
                value.prepare("image", "python", "storage", "node", "chart")
            value.install_crds.assert_not_called()

    def test_fault_injection_rejects_any_unapproved_dependency(self):
        value = Coordinator.__new__(Coordinator)
        value._scale_own = Mock()
        with self.assertRaises(ValueError):
            with value.outage("foreign-database"):
                self.fail("Unapproved outage was entered")
        value._scale_own.assert_not_called()

    def test_same_name_replacement_cannot_be_scaled_by_old_cleanup_context(self):
        with tempfile.TemporaryDirectory() as directory:
            pins = Path(directory)
            write_private(pins / "owned.json", canonical({"kind": "Deployment", "namespace": "trial-panel",
                "name": "panel", "uid": "original-uid"}))
            kube = Mock(return_value=SimpleNamespace(stdout=json.dumps({"metadata": {
                "uid": "replacement-uid", "resourceVersion": "10"}})))
            value = Coordinator.__new__(Coordinator)
            value.namespaces = {"panel": "trial-panel"}
            value.cluster = SimpleNamespace(pins=pins, kube=kube)
            with self.assertRaises(RuntimeError):
                value._scale_own("panel", "panel", 0)
            self.assertEqual(kube.call_count, 1)
            self.assertEqual(kube.call_args.args[0], "get")


if __name__ == "__main__":
    unittest.main()
