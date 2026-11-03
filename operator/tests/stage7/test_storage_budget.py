import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
from infrastructure import BUDGETS, BudgetCluster, Cluster
from manifests import LABEL


class StorageBudgetTests(unittest.TestCase):
    def render(self, role, names):
        source = {"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {LABEL: role}},
            "spec": {"containers": [{"name": name} for name in names]}}}}
        before = copy.deepcopy(source)
        with patch.object(Cluster, "create", lambda instance, value: value):
            answer = BudgetCluster.create(object.__new__(BudgetCluster), source)
        self.assertEqual(source, before)
        self.containers = answer["spec"]["template"]["spec"]["containers"]
        return {container["name"]: container["resources"]["limits"]["memory"] for container in self.containers}

    def test_storage_backend_grows_inside_existing_namespace_quota(self):
        values = self.render("storage", ["storage", "s3-1", "s3-2"])
        self.assertEqual(values, {"storage": "512Mi", "s3-1": "128Mi", "s3-2": "128Mi"})
        self.assertEqual(sum(int(value[:-2]) for value in values.values()), BUDGETS["storage"])
        self.assertEqual(sum(BUDGETS.values()), 4096)
        self.assertEqual(self.containers[0]["env"], [{"name": "GOMEMLIMIT", "value": "384MiB"}])
        self.assertNotIn("env", self.containers[1])
        self.assertNotIn("env", self.containers[2])

    def test_other_component_limits_are_not_broadened(self):
        self.assertEqual(self.render("journal-gateway", ["gateway"]), {"gateway": "128Mi"})
        self.assertEqual(self.render("witness", ["witness"]), {"witness": "128Mi"})


if __name__ == "__main__":
    unittest.main()
