"""Accelerated timing/guard tests; they never claim a real-duration soak."""

import base64
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from panel_cases import canonical, observe_jwt
from token_lifecycle import TokenLifecycle


class Clock:
    def __init__(self):
        self.value = 0

    def monotonic(self):
        return self.value

    def wall(self):
        return 1000 + self.value

    def sleep(self, seconds):
        self.value += seconds


def token(issued, expires):
    b64 = lambda value: base64.urlsafe_b64encode(canonical(value)).decode().rstrip("=")
    return b64({"alg": "EdDSA", "kid": "public-same-signing-key"}) + "." + b64({"iat": issued, "exp": expires,
        "kubernetes.io": {"namespace": "public-trial", "serviceaccount": {"name": "public-reader", "uid": "public-reader-uid"},
            "pod": {"name": "public-app", "uid": "public-pod-uid"}}}) + ".public-unsigned-test-only"


class Panel:
    def __init__(self, root, clock):
        self.root, self.clock, self.refreshes = root, clock, []

    def exchange(self, raw):
        if observe_jwt(raw)["exp"] <= self.clock.wall():
            raise RuntimeError("test expired token")

    def assert_token_refresh(self, old, new):
        self.exchange(old)
        self.exchange(new)
        before, after = observe_jwt(old), observe_jwt(new)
        if before["pod_uid"] != after["pod_uid"] or before["hash"] == after["hash"] or after["iat"] <= before["iat"]:
            raise RuntimeError("test invalid refresh")
        self.refreshes.append((before["iat"], after["iat"], self.clock.wall()))
        return {"samePodProjectedJWTRefreshed": True}


class TokenLifecycleGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage7.")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.clock = Clock()
        self.panel = Panel(self.root, self.clock)
        self.old, self.new = token(1000, 1600), token(1480, 2080)
        self.faults = []
        self.healthy_count = 0

    def reader(self):
        return {"token": self.new if self.clock.value >= 480 else self.old,
            "pod_uid": "public-pod-uid", "container_id": "containerd://" + "a" * 64}

    def healthy(self):
        self.healthy_count += 1
        return True

    @contextmanager
    def fault(self):
        self.faults.append("entered")
        try:
            self.clock.sleep(2)
            yield
        finally:
            self.clock.sleep(2)
            self.faults.append("restored")

    def runner(self, reader=None, healthy=None, faults=None):
        return TokenLifecycle(self.panel, reader or self.reader, healthy or self.healthy,
            faults or [("sealed", self.fault), ("revoked", self.fault), ("sealed", self.fault), ("revoked", self.fault)],
            _clock=self.clock.monotonic, _wall=self.clock.wall, _sleep=self.clock.sleep)

    def test_six_hundred_seconds_and_refresh_before_old_expiry_with_repeated_faults(self):
        result = self.runner().run()
        self.assertGreaterEqual(result["durationSeconds"], 600)
        self.assertFalse(result["realMonotonicClock"])  # This test is explicitly accelerated.
        self.assertEqual(result["faultsExecuted"], 4)
        self.assertEqual(result["authenticatedProjectedRefreshes"], 1)
        self.assertLess(self.panel.refreshes[0][2], 1600)
        self.assertGreater(self.healthy_count, 100)
        self.assertEqual(self.faults.count("restored"), 4)
        self.assertFalse(result["implicitJWKSRotationClaimed"])
        contents = b"".join(path.read_bytes() for path in self.root.rglob("*.json"))
        self.assertNotIn(self.old.encode(), contents)
        self.assertNotIn(self.new.encode(), contents)

    def test_no_refresh_cannot_pass_at_timeout(self):
        def reader():
            return dict(self.reader(), token=self.old)
        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            self.runner(reader=reader).run()
        self.assertFalse((self.root / "token-lifecycle-plain" / "complete.json").exists())

    def test_restarted_container_or_replaced_pod_is_not_a_projected_refresh(self):
        def reader():
            value = self.reader()
            if self.clock.value >= 300:
                value["container_id"] = "containerd://" + "b" * 64
            return value
        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            self.runner(reader=reader).run()
        self.assertEqual(self.panel.refreshes, [])

    def test_expired_old_token_is_not_used_as_an_authenticated_positive_control(self):
        self.old = token(1000, 1450)
        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            self.runner().run()
        self.assertEqual(self.panel.refreshes, [])

    def test_fault_timeout_is_failure_and_context_is_restored(self):
        @contextmanager
        def slow():
            try:
                self.clock.sleep(61)
                yield
            finally:
                self.faults.append("restored-slow")
        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            self.runner(faults=[("sealed", slow), ("revoked", self.fault)]).run()
        self.assertIn("restored-slow", self.faults)

    def test_callback_error_never_exposes_private_value_and_cannot_produce_completion(self):
        def broken():
            raise RuntimeError("public-private-value-must-not-appear")
        with self.assertRaises(RuntimeError) as caught:
            self.runner(healthy=broken).run()
        self.assertNotIn("public-private-value", str(caught.exception))
        self.assertFalse((self.root / "token-lifecycle-plain" / "complete.json").exists())

    def test_no_silent_resume_of_an_interrupted_monotonic_proof(self):
        runner = self.runner()
        runner.run()
        before = self.healthy_count
        with self.assertRaisesRegex(RuntimeError, "cannot reset"):
            runner.run()
        self.assertEqual(before, self.healthy_count)


if __name__ == "__main__":
    unittest.main()
