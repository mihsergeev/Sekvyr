"""Exact first-publish continuation guards, without any real actions."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
from fixture import canonical
from app_modes import LABEL, ROLE, require
from plain_initial_resume import resume_initial_after_publish


class InitialResumeGuards(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.pair = {"generation": "public-synthetic-generation", "demo": "public-synthetic-canary"}
        (self.root / "initial-values.json").write_bytes(canonical(self.pair))
        image = "docker.io/library/python@sha256:" + "a" * 64
        self.apps, self.sources, pins = {}, {}, {}
        for name, mode, source_file in (("plain-env-app", "env", Path(__file__).resolve().parents[1] / "stage5" / "app.py"),
                ("plain-volume-app", "volume", Path(__file__).resolve().with_name("file_app.py"))):
            container = {"name": "app", "image": image, "command": ["python", "-B", "/app/app.py"],
                "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True}]}
            volumes = [{"name": "source", "configMap": {"name": name + "-source", "defaultMode": 420}}]
            if mode == "env":
                container["envFrom"] = [{"secretRef": {"name": "plain-runtime-env"}}]
            else:
                container["command"] += ["--mode", "volume"]
                container["volumeMounts"].append({"name": "secrets", "mountPath": "/secrets", "readOnly": True})
                volumes.append({"name": "secrets", "secret": {"secretName": "plain-runtime-env", "defaultMode": 288}})
            self.apps[name] = {"metadata": {"uid": "created-" + name}, "spec": {"replicas": 0,
                "selector": {"matchLabels": {LABEL: name}}, "template": {"metadata": {"labels": {LABEL: name, ROLE: "application"}},
                    "spec": {"automountServiceAccountToken": False, "containers": [container], "volumes": volumes}}}}
            self.sources[name + "-source"] = {"metadata": {"uid": "created-" + name + "-source"},
                "immutable": True, "data": {"app.py": source_file.read_text(encoding="utf-8")}}
            pins["Deployment", name] = {"uid": "created-" + name}
            pins["ConfigMap", name + "-source"] = {"uid": "created-" + name + "-source"}
        self.events = []
        def scale(kind, name, ops):
            require(ops == [{"op": "replace", "path": "/spec/replicas", "value": 1}], "Only initial own app scale allowed")
            self.events.append("scale-" + name)
            self.apps[name]["spec"]["replicas"] = 1
        self.current = Mock(return_value={"verified": True})
        lifecycle = SimpleNamespace(managed={"role": {"manifest": {"kind": "Role"}, "uid": "created-role"}},
            _external_guard=Mock(), _retained_guard=Mock(), _get=Mock(return_value={}), _owned=Mock(), _matches=Mock())
        installation = SimpleNamespace(namespace="synthetic-isolation", binding={"target": {"name": "plain-runtime-env"}}, lifecycle=lifecycle,
            current=self.current, target_ref=Mock(return_value={"name": "plain-runtime-env", "uid": "runtime-created-target"}))
        def footprint(name):
            return {"pods": [] if self.apps[name]["spec"]["replicas"] == 0 else ["created-pod"], "replica_sets": ["created-rs"]}
        modes = SimpleNamespace(namespace=installation.namespace, python_image=image, modes={}, owned=SimpleNamespace(pins=pins,
            get=lambda kind, name: copy.deepcopy(self.sources[name] if kind == "ConfigMap" else self.apps[name]), patch=scale),
            footprint=footprint, status=lambda name: {"generation": self.pair["generation"],
                "value_digest": hashlib.sha256(self.pair["demo"].encode("utf-8")).hexdigest()}, capture=lambda name: {"public": True})
        self.cluster = SimpleNamespace(kube=Mock(return_value=SimpleNamespace(stdout='{"items":[]}')))
        self.cases = SimpleNamespace(installation=installation, c=SimpleNamespace(cluster=self.cluster), root=self.root, apps=modes,
            env_name="plain-env-app", volume_name="plain-volume-app", target_name="plain-runtime-env",
            proof=Mock(return_value={"status": "PASS"}), publish=Mock(side_effect=AssertionError("No republish")),
            pair=Mock(side_effect=AssertionError("No pair regeneration")), poke=Mock(side_effect=AssertionError("No new poke")))
        self.frame = {"self": self.cases, "p": installation, "pair": self.pair, "before": "2026-01-01T00:00:00Z"}

    def test_exact_tail_waits_and_scales_only_two_apps_no_republish(self):
        result = resume_initial_after_publish(self.cases, self.frame)
        self.assertEqual(result, {"status": "PASS"})
        self.assertEqual(self.events, ["scale-plain-env-app", "scale-plain-volume-app"])
        self.current.assert_called_once_with(after_success=self.frame["before"])
        self.cases.installation.target_ref.assert_called_once_with(self.pair["generation"], self.pair["demo"], after_success=self.frame["before"])
        self.cases.publish.assert_not_called()
        self.cases.pair.assert_not_called()
        self.cases.poke.assert_not_called()
        self.assertIs(self.cases.selected, self.pair)
        self.assertEqual(set(self.cases.baselines), set(self.apps))
        self.assertEqual(self.cases.apps.modes, {"plain-env-app": "env", "plain-volume-app": "volume"})
        with self.assertRaises(RuntimeError):
            resume_initial_after_publish(self.cases, self.frame)

    def test_foreign_frame_or_changed_saved_pair_refused_before_scale(self):
        self.frame["p"] = object()
        with self.assertRaises(RuntimeError):
            resume_initial_after_publish(self.cases, self.frame)
        self.frame["p"] = self.cases.installation
        (self.root / "initial-values.json").write_bytes(canonical(dict(self.pair, demo="changed-canary")))
        with self.assertRaises(RuntimeError):
            resume_initial_after_publish(self.cases, self.frame)
        self.assertFalse(self.events)

    def test_stale_current_timeout_cannot_scale_or_claim_proof(self):
        self.current.return_value = False
        def once(check):
            require(check(), "Synthetic fresh status timeout")
        with patch("plain_initial_resume.wait", side_effect=once), self.assertRaises(RuntimeError):
            resume_initial_after_publish(self.cases, self.frame)
        self.assertFalse(self.events)
        self.cases.proof.assert_not_called()

    def test_started_app_or_target_proof_failure_cannot_scale(self):
        self.apps["plain-env-app"]["spec"]["replicas"] = 1
        with self.assertRaises(RuntimeError):
            resume_initial_after_publish(self.cases, self.frame)
        self.apps["plain-env-app"]["spec"]["replicas"] = 0
        self.cases.installation.target_ref.side_effect = RuntimeError("Protected target mismatch")
        with self.assertRaises(RuntimeError):
            resume_initial_after_publish(self.cases, self.frame)
        self.assertFalse(self.events)

    def test_physical_old_or_foreign_pod_cannot_be_ignored_by_zero_replicas(self):
        self.cluster.kube.return_value.stdout = '{"items":[{"metadata":{"uid":"old-physical-pod"}}]}'
        with self.assertRaises(RuntimeError):
            resume_initial_after_publish(self.cases, self.frame)
        self.assertFalse(self.events)
        self.cases.proof.assert_not_called()

    def _reject_mismatched_demo(self, wrong_app):
        original = self.cases.apps.status
        self.cases.apps.status = lambda name: dict(original(name), value_digest="wrong-public-digest") if name == wrong_app else original(name)
        with self.assertRaisesRegex(RuntimeError, "value differs"):
            resume_initial_after_publish(self.cases, self.frame)
        self.cases.proof.assert_not_called()
        self.assertFalse(hasattr(self.cases, "baselines"))

    def test_matched_generation_but_wrong_env_demo_cannot_claim_pass(self):
        self._reject_mismatched_demo("plain-env-app")

    def test_matched_generation_but_wrong_volume_demo_cannot_claim_pass(self):
        self._reject_mismatched_demo("plain-volume-app")

    def test_conflicting_existing_modes_rejected_before_scale(self):
        self.cases.apps.modes["plain-volume-app"] = "file"
        with self.assertRaisesRegex(RuntimeError, "Conflicting"):
            resume_initial_after_publish(self.cases, self.frame)
        self.assertFalse(self.events)
        self.cases.proof.assert_not_called()
        self.assertEqual(self.cases.apps.modes, {"plain-volume-app": "file"})

    def test_wrong_command_mount_target_or_image_cannot_restore_modes(self):
        spec = self.apps["plain-volume-app"]["spec"]["template"]["spec"]
        original = copy.deepcopy(spec)
        def command(value):
            value["containers"][0]["command"] = ["python", "/other.py"]
        def mount(value):
            value["containers"][0]["volumeMounts"][1]["readOnly"] = False
        def target(value):
            value["volumes"][1]["secret"]["secretName"] = "foreign-target"
        def image(value):
            value["containers"][0]["image"] = "docker.io/library/python@sha256:" + "b" * 64
        for mutate in (command, mount, target, image):
            with self.subTest(mutation=mutate.__name__):
                spec.clear()
                spec.update(copy.deepcopy(original))
                mutate(spec)
                with self.assertRaises(RuntimeError):
                    resume_initial_after_publish(self.cases, self.frame)
                self.assertFalse(self.events)
                self.assertEqual(self.cases.apps.modes, {})
                self.cases.proof.assert_not_called()

    def test_source_uid_bytes_and_immutable_flag_must_match_creation(self):
        name = "plain-env-app-source"
        original = copy.deepcopy(self.sources[name])
        for field in ("uid", "bytes", "immutable"):
            with self.subTest(field=field):
                source = copy.deepcopy(original)
                if field == "uid":
                    source["metadata"]["uid"] = "foreign-source-uid"
                elif field == "bytes":
                    source["data"]["app.py"] += "\n# unexpected synthetic edit\n"
                else:
                    source["immutable"] = False
                self.sources[name] = source
                with self.assertRaisesRegex(RuntimeError, "immutable source"):
                    resume_initial_after_publish(self.cases, self.frame)
                self.assertFalse(self.events)
                self.assertEqual(self.cases.apps.modes, {})
                self.cases.proof.assert_not_called()

    def test_wrong_envfrom_target_cannot_restore_env_mode(self):
        self.apps["plain-env-app"]["spec"]["template"]["spec"]["containers"][0]["envFrom"][0]["secretRef"]["name"] = "foreign-env-target"
        with self.assertRaisesRegex(RuntimeError, "target flow"):
            resume_initial_after_publish(self.cases, self.frame)
        self.assertFalse(self.events)
        self.assertEqual(self.cases.apps.modes, {})


if __name__ == "__main__":
    unittest.main()
