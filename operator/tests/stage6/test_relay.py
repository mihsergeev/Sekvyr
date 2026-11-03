"""The trial relay cannot grant permission, leak payloads or block new barriers."""

import concurrent.futures
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from admission_relay import Relay, admission_path, encoded


class RelayGuards(unittest.TestCase):
    def test_real_admission_timeout_hint_is_bounded_and_cannot_change_route(self):
        for path in ("/admit", "/admit?timeout=1s", "/admit?timeout=30s"):
            self.assertTrue(admission_path(path), path)
        for path in ("/admit?timeout=0s", "/admit?timeout=31s", "/admit?timeout=01s", "/admit?timeout=1.5s",
                     "/admit?timeout=30s&timeout=1s", "/admit?timeout=30s&other=1", "/admit?%74imeout=30s",
                     "/admit/else?timeout=30s", "//admit?timeout=30s", "/admit?timeout=30s#fragment"):
            self.assertFalse(admission_path(path), path)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-relay-unit-")
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.relay = Relay.__new__(Relay)
        self.relay.state = self.state
        self.relay.lock = threading.Lock()
        self.relay.claimed = False
        self.relay.config = {"upstream_origin": "https://fencer.example.test", "namespace": "trial-apps", "name": "values",
            "target_uid": "public-target-uid", "operator_username": "system:serviceaccount:trial-apps:operator",
            "operator_sa_uid": "public-account-uid", "old_pod_uid": "public-old-pod-uid", "kind": "Secret",
            "api_version": "v1", "maximum_hold_seconds": 0.5,
            "request_marker": "a" * 32, "expected_resource_version": "11"}
        obj = {"apiVersion": "v1", "kind": "Secret", "metadata": {"namespace": "trial-apps", "name": "values",
            "uid": "public-target-uid", "resourceVersion": "11"}, "data": {"DEMO": "synthetic-payload-must-not-be-written"}}
        self.review = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": {
            "uid": "public-review-uid", "operation": "UPDATE", "namespace": "trial-apps", "name": "values",
            "object": obj, "oldObject": copy.deepcopy(obj), "userInfo": {"username": self.relay.config["operator_username"],
                "uid": "public-account-uid", "extra": {"authentication.kubernetes.io/pod-uid": ["public-old-pod-uid"]}}}}
        self.review["request"]["object"]["metadata"]["annotations"] = {"stage6-trial-late-write": "a" * 32}

    def verdict(self, allowed=True):
        return encoded({"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
                        "response": {"uid": "public-review-uid", "allowed": allowed}})

    def test_real_deny_is_returned_without_hold_or_permission_upgrade(self):
        raw = self.verdict(False)
        with patch.object(self.relay, "forward", return_value=raw) as upstream:
            self.assertEqual(self.relay.handle(encoded(self.review)), raw)
            upstream.assert_called_once()
        self.assertFalse((self.state / "held.json").exists())

    def test_upstream_allowed_is_held_while_new_owner_verdict_passes(self):
        raw = self.verdict()
        with patch.object(self.relay, "forward", return_value=raw), concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.relay.handle, encoded(self.review))
            deadline = time.monotonic() + 0.3
            while not (self.state / "held.json").exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertTrue((self.state / "held.json").exists())
            self.assertFalse(pending.done())
            new_owner = copy.deepcopy(self.review)
            new_owner["request"]["userInfo"]["extra"]["authentication.kubernetes.io/pod-uid"] = ["public-new-pod-uid"]
            self.assertEqual(self.relay.handle(encoded(new_owner)), raw)
            saved = (self.state / "held.json").read_text(encoding="utf-8")
            self.assertNotIn("synthetic-payload", saved)
            self.assertNotIn("DEMO", saved)
            self.assertTrue(json.loads(saved)["upstream_allowed"])
            (self.state / "release").write_text("release exact held verdict", encoding="utf-8")
            self.assertEqual(pending.result(timeout=1), raw)

    def test_timeout_or_wrong_upstream_uid_fails_closed(self):
        self.relay.config["maximum_hold_seconds"] = 0.01
        with patch.object(self.relay, "forward", return_value=self.verdict()):
            result = json.loads(self.relay.handle(encoded(self.review)))
        self.assertFalse(result["response"]["allowed"])
        self.assertTrue((self.state / "held.json").exists())
        wrong = json.loads(self.verdict())
        wrong["response"]["uid"] = "different-request"
        with patch.object(self.relay, "forward", return_value=encoded(wrong)):
            self.assertFalse(json.loads(self.relay.handle(encoded(self.review)))["response"]["allowed"])

    def test_replacement_target_or_dryrun_never_matches(self):
        self.assertTrue(self.relay.matches(self.review["request"]))
        for which in ("target", "account", "pod", "rv", "dryrun"):
            request = copy.deepcopy(self.review["request"])
            if which == "target":
                request["object"]["metadata"]["uid"] = "replacement"
            elif which == "account":
                request["userInfo"]["uid"] = "replacement"
            elif which == "pod":
                request["userInfo"]["extra"]["authentication.kubernetes.io/pod-uid"].append("other")
            elif which == "rv":
                request["object"]["metadata"]["resourceVersion"] = "12"
            else:
                request["dryRun"] = True
            with self.subTest(which=which):
                self.assertFalse(self.relay.matches(request))

    def test_background_or_replayed_marker_cannot_claim_the_external_request(self):
        background = copy.deepcopy(self.review)
        background["request"]["object"]["metadata"].pop("annotations")
        with patch.object(self.relay, "forward", return_value=self.verdict()):
            self.assertEqual(self.relay.handle(encoded(background)), self.verdict())
        self.assertFalse(self.relay.claimed)
        self.assertFalse((self.state / "held.json").exists())
        for which in ("wrong-marker", "old-marker", "different-rv"):
            review = copy.deepcopy(self.review)
            if which == "wrong-marker":
                review["request"]["object"]["metadata"]["annotations"]["stage6-trial-late-write"] = "b" * 32
            elif which == "old-marker":
                review["request"]["oldObject"]["metadata"]["annotations"] = {"stage6-trial-late-write": "a" * 32}
            else:
                for key in ("object", "oldObject"):
                    review["request"][key]["metadata"]["resourceVersion"] = "12"
            self.assertFalse(self.relay.matches(review["request"]), which)


if __name__ == "__main__":
    unittest.main()
