import copy
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
import resume_e2e_change as resume
from application import REVISION


class ResumeChangeTests(unittest.TestCase):
    def fixture(self):
        original = {"snapshot": {"sequence": "2", "envelope_hash": "a" * 64},
            "old": {"pod_uid": "old-pod", "boot_id": "old-boot"},
            "before": {"replica_sets": ["old-rs"], "template": {"metadata": {}, "spec": {"fixed": True}}}}
        self.after = copy.deepcopy(original["before"])
        self.after["replica_sets"].append("new-rs")
        self.after["template"]["metadata"]["annotations"] = {"secrets.sekvyr.ru/restart-target-uid": "opaque"}
        self.status = {"pod_uid": "new-pod", "boot_id": "new-boot", "generation": "selected", "value_digest": hashlib.sha256(b"synthetic-demo").hexdigest()}
        self.current = {"snapshot": copy.deepcopy(original["snapshot"])}
        case = SimpleNamespace(installed=True, selected={"generation": "selected", "demo": "synthetic-demo"},
            c=SimpleNamespace(current=lambda: self.current, publish=Mock()), pair=lambda label: {"generation": "selected", "demo": "synthetic-demo"},
            app=SimpleNamespace(current=lambda *args: True, status=lambda: self.status, footprint=lambda: self.after,
                get=lambda *args: {"metadata": {"uid": "target-uid", "annotations": {REVISION: "opaque"}}}),
            proof=Mock(side_effect=lambda label, facts: facts))
        return case, original

    def test_same_original_change_finishes_without_publication(self):
        case, original = self.fixture()
        with patch.object(resume, "wait", side_effect=lambda callback, **kwargs: callback()):
            result = resume.run(case, original)
        self.assertFalse(result["repeatPublication"])
        case.c.publish.assert_not_called()
        case.proof.assert_called_once()

    def test_advanced_canonical_head_cannot_rebase(self):
        case, original = self.fixture()
        self.current["snapshot"]["sequence"] = "3"
        with self.assertRaises(RuntimeError):
            resume.run(case, original)
        case.proof.assert_not_called()

    def test_extra_replicaset_cannot_produce_pass(self):
        case, original = self.fixture()
        self.after["replica_sets"].append("extra-rs")
        with patch.object(resume, "wait", side_effect=lambda callback, **kwargs: callback()), self.assertRaises(RuntimeError):
            resume.run(case, original)
        case.proof.assert_not_called()

    def test_same_process_cannot_produce_pass(self):
        case, original = self.fixture()
        self.status.update(original["old"])
        with patch.object(resume, "wait", side_effect=lambda callback, **kwargs: callback()), self.assertRaises(RuntimeError):
            resume.run(case, original)
        case.proof.assert_not_called()


if __name__ == "__main__":
    unittest.main()
