import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
import fresh_target_retry as retry


class FreshRetryGuards(unittest.TestCase):
    def fixture(self):
        self.cr = {"metadata": {"uid": "cr-uid", "generation": 1}, "status": {"observedGeneration": 1,
            "observedStoreUID": "store-uid", "observedStoreGeneration": 2, "lastAttemptTime": "2026-01-01T00:00:01Z",
            "conditions": [{"type": "DataCurrent", "status": "False", "reason": "PanelUnavailable", "observedGeneration": 1},
                {"type": "BootstrapReady", "status": "True", "observedGeneration": 1},
                {"type": "WitnessReady", "status": "Unknown", "reason": "NotApplicablePlain"}]}}
        self.store = {"metadata": {"uid": "store-uid", "generation": 2}}
        return SimpleNamespace(owned=SimpleNamespace(get=lambda kind, name: copy.deepcopy(self.store if kind == "SekvyrStore" else self.cr)))

    def test_valid_unavailability_needs_plain_bootstrap(self):
        p = self.fixture()
        self.assertTrue(retry._status(p, False))

    def test_wrong_failure_reason_cannot_prove_transport_failure(self):
        p = self.fixture()
        self.cr["status"]["conditions"][0]["reason"] = "StateInvalid"
        with self.assertRaises(RuntimeError):
            retry._status(p, False)

    def test_bootstrap_failure_cannot_prove_transport_failure(self):
        p = self.fixture()
        self.cr["status"]["conditions"][1]["status"] = "False"
        with self.assertRaises(RuntimeError):
            retry._status(p, False)

    def test_success_history_cannot_prove_first_target_failure(self):
        p = self.fixture()
        self.cr["status"]["lastSuccessfulSyncTime"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(RuntimeError):
            retry._status(p, False)

    def test_replaced_store_is_not_current(self):
        p = self.fixture()
        self.cr["status"]["observedStoreUID"] = "another-store"
        self.assertFalse(retry._status(p, False))

    def test_stale_generation_is_not_current(self):
        p = self.fixture()
        self.cr["status"]["conditions"][0]["observedGeneration"] = 0
        self.assertFalse(retry._status(p, False))

    def test_plain_cannot_claim_a_witness_checkpoint(self):
        p = self.fixture()
        self.cr["status"]["lastVerifiedCheckpoint"] = {"sequence": "1"}
        with self.assertRaises(RuntimeError):
            retry._status(p, False)

    def test_success_requires_fresh_attempt_timestamp(self):
        p = self.fixture()
        self.cr["status"]["conditions"][0]["status"] = "True"
        self.cr["status"]["lastSuccessfulSyncTime"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(RuntimeError):
            retry._status(p, True)


if __name__ == "__main__":
    unittest.main()
