import copy
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from fresh_helm_sync import FreshHelmSync


class App:
    def __init__(self):
        self.pokes = 0
        self.cr = {"metadata": {"generation": 2}, "spec": {"storeRef": {"name": "application-secrets", "uid": "public-test-store"}},
            "status": {"observedGeneration": 2, "observedStoreUID": "public-test-store", "observedStoreGeneration": 3,
                "lastVerifiedCheckpoint": {"sequence": "5", "envelopeHash": "a" * 64},
                "lastSuccessfulSyncTime": "2030-01-01T00:00:02Z", "lastAttemptTime": "2030-01-01T00:00:02Z",
                "conditions": [{"type": name, "status": "True", "observedGeneration": 2} for name in
                    ("Ready", "BootstrapReady", "WitnessReady", "DataCurrent", "RolloutReady")]}}
        self.store = {"metadata": {"uid": "public-test-store", "generation": 3}}

    def get(self, kind, name):
        return copy.deepcopy(self.cr if kind == "SekvyrSecret" else self.store)

    def poke(self):
        self.pokes += 1


class FreshHelmSyncGuards(unittest.TestCase):
    def make(self, app=None, **overrides):
        app = app or App()
        kwargs = dict(cutover=datetime(2030, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
            baseline_last_success="2030-01-01T00:00:01Z", expected_cr_generation=2,
            expected_store_uid="public-test-store", expected_store_generation=3, old_owned_fencers_absent=True)
        kwargs.update(overrides)
        return app, FreshHelmSync(app, {"sequence": "5", "envelope_hash": "a" * 64}, **kwargs)

    def test_accepts_only_post_cutover_success_without_mutation(self):
        app, gate = self.make()
        self.assertTrue(gate.current())
        self.assertEqual(app.pokes, 0)

    def test_stored_success_cannot_start_stability_clock(self):
        app, gate = self.make(baseline_last_success="2030-01-01T00:00:02Z")
        self.assertFalse(gate.current())
        app.cr["status"]["lastSuccessfulSyncTime"] = "2030-01-01T00:00:03Z"
        app.cr["status"]["lastAttemptTime"] = "2030-01-01T00:00:03Z"
        self.assertTrue(gate.current())

    def test_newer_than_baseline_but_before_cutover_is_not_fresh(self):
        app, gate = self.make(cutover=datetime(2030, 1, 1, 0, 0, 3, tzinfo=timezone.utc))
        self.assertFalse(gate.current())

    def test_later_failed_attempt_cannot_reuse_last_success(self):
        app, gate = self.make()
        app.cr["status"]["lastAttemptTime"] = "2030-01-01T00:00:03Z"
        self.assertFalse(gate.current())

    def test_stale_observation_or_wrong_checkpoint_is_not_accepted(self):
        for field, value in (("observedGeneration", 1), ("observedStoreUID", "other"),
                             ("observedStoreGeneration", 2), ("lastVerifiedCheckpoint", {})):
            with self.subTest(field=field):
                app, gate = self.make()
                app.cr["status"][field] = value
                self.assertFalse(gate.current())

    def test_all_conditions_require_current_generation_and_unique_types(self):
        for name in ("Ready", "BootstrapReady", "WitnessReady", "DataCurrent", "RolloutReady"):
            for field, value in (("status", "False"), ("observedGeneration", 1)):
                app, gate = self.make()
                next(item for item in app.cr["status"]["conditions"] if item["type"] == name)[field] = value
                self.assertFalse(gate.current())
        app, gate = self.make()
        app.cr["status"]["conditions"].append(app.cr["status"]["conditions"][0])
        self.assertFalse(gate.current())

    def test_replaced_or_changed_inputs_fail_hard(self):
        for mutation in (lambda a: a.store["metadata"].update(uid="other"),
                         lambda a: a.store["metadata"].update(generation=4),
                         lambda a: a.cr["metadata"].update(generation=3),
                         lambda a: a.cr["spec"]["storeRef"].update(uid="other"),
                         lambda a: a.cr["spec"].update(suspend=True),
                         lambda a: a.cr["metadata"].update(deletionTimestamp="present")):
            app, gate = self.make()
            mutation(app)
            with self.assertRaises(RuntimeError):
                gate.current()

    def test_cutover_requires_explicit_pod_absence_and_utc(self):
        for overrides in ({"old_owned_fencers_absent": False}, {"cutover": datetime(2030, 1, 1)},
                          {"baseline_last_success": "2030-01-01T00:00:03Z"}):
            with self.assertRaises(RuntimeError):
                self.make(**overrides)

    def test_wait_optional_poke_and_timeout_never_promote_stale_status(self):
        app, gate = self.make()
        self.assertTrue(gate.wait(poke=True))
        self.assertEqual(app.pokes, 1)
        app, gate = self.make(baseline_last_success="2030-01-01T00:00:02Z")
        with patch("fresh_helm_sync.time.monotonic", side_effect=[0, 1]):
            with self.assertRaisesRegex(RuntimeError, "was not observed"):
                gate.wait(timeout=1)
        self.assertEqual(app.pokes, 0)

    def test_invalid_timestamp_has_fixed_safe_error(self):
        app, gate = self.make()
        app.cr["status"]["lastSuccessfulSyncTime"] = "private-placeholder-not-a-timestamp"
        with self.assertRaisesRegex(RuntimeError, "^Fresh Helm synchronization proof is invalid$"):
            gate.current()


if __name__ == "__main__":
    unittest.main()
