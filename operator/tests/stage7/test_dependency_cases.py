import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
import dependency_cases as dependency


class DependencyGuards(unittest.TestCase):
    def value(self, reason="PanelUnavailable"):
        return {"metadata": {"generation": 2}, "status": {"lastAttemptTime": "2026-01-01T00:00:02Z", "conditions": [
            {"type": "DataCurrent", "status": "False", "reason": reason, "observedGeneration": 2},
            {"type": "BootstrapReady", "status": "True", "observedGeneration": 2}]}}

    def test_precise_dependency_reasons_are_required(self):
        before = "2026-01-01T00:00:01Z"
        for label, reason in (("panel", "PanelUnavailable"), ("witness", "WitnessUnavailable"), ("fencer", "FencingUnavailable"), ("gateway", "JournalUnavailable")):
            self.assertTrue(dependency._failed_status(self.value(reason), label, before))
        self.assertFalse(dependency._failed_status(self.value("StateInvalid"), "panel", before))
        self.assertFalse(dependency._failed_status(self.value("JournalUnavailable"), "panel", before))

    def test_failure_must_follow_actual_stop(self):
        value = self.value()
        self.assertFalse(dependency._failed_status(value, "panel", value["status"]["lastAttemptTime"]))
        self.assertFalse(dependency._failed_status(value, "panel", "2026-01-01T00:00:03Z"))

    def test_bad_or_stale_bootstrap_cannot_count_as_transport_failure(self):
        for field, changed in (("status", "False"), ("observedGeneration", 1)):
            value = self.value()
            value["status"]["conditions"][1][field] = changed
            self.assertFalse(dependency._failed_status(value, "panel", "2026-01-01T00:00:01Z"))

    def test_stale_data_generation_cannot_count(self):
        value = self.value()
        value["status"]["conditions"][0]["observedGeneration"] = 1
        self.assertFalse(dependency._failed_status(value, "panel", "2026-01-01T00:00:01Z"))

    def scope(self, endpoints=None, owner="service-uid"):
        item = {"metadata": {"namespace": "owned", "ownerReferences": [{"kind": "Service", "uid": owner}]}, "endpoints": endpoints}
        return SimpleNamespace(namespace="owned", get=lambda *args: {"metadata": {"uid": "service-uid"}},
            cluster=SimpleNamespace(kube=lambda *args: SimpleNamespace(stdout=json.dumps({"items": [item]}))))

    def test_null_endpoints_are_empty_and_unknown_ready_is_not_empty(self):
        self.assertTrue(dependency._no_endpoints(self.scope(), "service"))
        self.assertFalse(dependency._no_endpoints(self.scope([{"conditions": {}}]), "service"))

    def test_foreign_endpoint_owner_cannot_prove_outage(self):
        with self.assertRaises(RuntimeError):
            dependency._no_endpoints(self.scope([], "foreign"), "service")

    def test_malformed_endpoint_list_fails(self):
        for endpoints in ({}, "bad", [None]):
            with self.assertRaises(RuntimeError):
                dependency._no_endpoints(self.scope(endpoints), "service")


if __name__ == "__main__":
    unittest.main()
