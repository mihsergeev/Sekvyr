import copy
from pathlib import Path
import sys
import unittest

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
from readiness_upgrade import review_diff


class ReadinessDiffGuards(unittest.TestCase):
    def fixture(self):
        before = [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "stage6-fencer", "namespace": "owned"},
            "spec": {"template": {"spec": {"containers": [{"name": "fencer", "image": "pinned", "resources": {"limits": {"memory": "160Mi"}},
                "readinessProbe": {"httpGet": {"path": "/readyz", "scheme": "HTTPS", "port": "https"}},
                "livenessProbe": {"httpGet": {"path": "/healthz", "scheme": "HTTPS", "port": "https"}}}]}}}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "trusted", "namespace": "owned"}, "data": {"config": "fixed"}}]
        after = copy.deepcopy(before)
        container = after[0]["spec"]["template"]["spec"]["containers"][0]
        container["readinessProbe"].update(timeoutSeconds=10, periodSeconds=10, failureThreshold=3, successThreshold=1)
        container["livenessProbe"].update(timeoutSeconds=1, periodSeconds=10, failureThreshold=3, successThreshold=1)
        return before, after

    def test_only_reviewed_probe_timeout_and_explicit_defaults(self):
        review_diff(*self.fixture())

    def test_health_gate_cannot_be_replaced_by_process_health(self):
        before, after = self.fixture()
        after[0]["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["path"] = "/healthz"
        with self.assertRaises(RuntimeError):
            review_diff(before, after)

    def test_other_resource_or_private_config_cannot_change(self):
        before, after = self.fixture()
        after[1]["data"]["config"] = "changed"
        with self.assertRaises(RuntimeError):
            review_diff(before, after)

    def test_container_resource_policy_is_preserved(self):
        before, after = self.fixture()
        after[0]["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = "512Mi"
        with self.assertRaises(RuntimeError):
            review_diff(before, after)

    def test_no_new_or_removed_resources(self):
        before, after = self.fixture()
        after.pop()
        with self.assertRaises(RuntimeError):
            review_diff(before, after)


if __name__ == "__main__":
    unittest.main()
