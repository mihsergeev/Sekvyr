"""Local fixture guards; these do not claim Kubernetes acceptance or reload."""

import copy
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app_modes import Stage7Applications
import file_app

IMAGE = "example.invalid/python@sha256:" + "1" * 64
AGENT = "ghcr.io/mihsergeev/sekvyr-agent@sha256:efa4b55850a1e0ea5b31907991dae8fa163bb7218c648dc8d8b609b90d96d884"


class FakeCluster:
    def __init__(self, root):
        self.task, self.pins = Path(root), Path(root) / "pins"
        self.pins.mkdir()
        self.namespaces, self.namespace_uid, self.objects, self.calls = {"trial-apps"}, "namespace-own", {}, []

    def namespace_pins(self):
        return {"trial-apps": "namespace-own"}

    def create(self, value):
        value = copy.deepcopy(value)
        meta = value["metadata"]
        key = value["kind"], meta["name"]
        if key in self.objects:
            raise RuntimeError("No fake adoption")
        meta.update(uid="created-" + str(len(self.objects)), resourceVersion="1")
        self.objects[key] = value
        pin = dict(kind=key[0], name=key[1], namespace=meta["namespace"], uid=meta["uid"])
        (self.pins / (str(len(self.objects)) + ".json")).write_text(json.dumps(pin), encoding="utf-8")
        return copy.deepcopy(value)

    def kube(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:2] == ("get", "namespace"):
            value = {"metadata": {"uid": self.namespace_uid}}
        elif args[0] == "get":
            value = self.objects[(args[1], args[2])]
        elif args[0] == "patch":
            value = copy.deepcopy(self.objects[(args[1], args[2])])
        else:
            raise AssertionError("Unexpected fake Kubernetes call")
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(value), stderr="")


class AppGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cluster = FakeCluster(self.temp.name)
        self.app = Stage7Applications(self.cluster, "trial-apps", IMAGE, AGENT)

    def test_images_and_namespace_are_explicit(self):
        for image in ("python:latest", "python:3", IMAGE + "suffix"):
            with self.assertRaises(RuntimeError):
                Stage7Applications(self.cluster, "trial-apps", image)
        with self.assertRaises(RuntimeError):
            Stage7Applications(self.cluster, "foreign", IMAGE)

    def test_replaced_namespace_blocks_create(self):
        self.cluster.namespace_uid = "replacement"
        with self.assertRaises(RuntimeError):
            self.app.owned.create_service_account("reader")
        self.assertFalse(self.cluster.objects)

    def test_unavailable_before_target_is_not_adopted(self):
        deployment = self.app.create_env("waiting", "future-target", replicas=0)
        self.assertEqual(deployment["spec"]["replicas"], 0)
        self.assertEqual(deployment["spec"]["template"]["spec"]["containers"][0]["envFrom"], [{"secretRef": {"name": "future-target"}}])
        self.assertNotIn(("Secret", "future-target"), self.app.owned.pins)
        with self.assertRaises(RuntimeError):
            self.app.create_env("running", "future-target")

    def test_runtime_target_is_readonly_and_exact_uid(self):
        self.cluster.objects[("Secret", "generated")] = {"kind": "Secret", "metadata": {
            "name": "generated", "namespace": "trial-apps", "uid": "protected-state-uid"}}
        self.app.target({"name": "generated", "uid": "protected-state-uid"})
        self.assertFalse(list(self.cluster.pins.glob("*.json")))
        with self.assertRaises(RuntimeError):
            self.app.target({"name": "generated", "uid": "other"})
        with self.assertRaises(RuntimeError):
            self.app.target("generated")
        self.assertTrue(all(call[0][0] == "get" for call in self.cluster.calls))

    def test_volume_standard_projection_and_no_rollout_hook(self):
        value = self.app.create_volume("volume", "future", replicas=0)
        spec = value["spec"]["template"]["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["volumes"][1]["secret"], {"secretName": "future", "defaultMode": 288})
        self.assertNotIn("subPath", spec["containers"][0]["volumeMounts"][1])
        self.assertTrue(all(value == "false" for value in value["metadata"]["annotations"].values()))

    def test_agent_original_entrypoint_shared_file_and_token_isolation(self):
        self.app.owned.create_service_account("agent-reader")
        self.app.owned.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "ca", "namespace": "trial-apps"}, "immutable": True, "data": {"ca.crt": "public-test-ca"}})
        route = {"SEKVYR_URL": "https://panel.example.invalid", "SEKVYR_PROJECT": "trial", "SEKVYR_ENV": "test"}
        value = self.app.create_agent("agent", route, "agent-reader", {"name": "ca", "key": "ca.crt"})
        spec = value["spec"]["template"]["spec"]
        app, agent = spec["containers"]
        self.assertEqual(agent["image"], AGENT)
        self.assertEqual(spec["initContainers"][0]["image"], AGENT)
        self.assertNotIn("command", agent)
        self.assertNotIn("command", spec["initContainers"][0])
        self.assertTrue(agent["args"][-2:] == ["--no-update", "--no-cache"])
        self.assertEqual([mount["name"] for mount in app["volumeMounts"]], ["source", "secrets"])
        token = spec["volumes"][2]["projected"]["sources"][0]["serviceAccountToken"]
        self.assertEqual(token, {"path": "token", "audience": "sekvyr", "expirationSeconds": 600})
        self.assertEqual(spec["securityContext"]["runAsUser"], 65534)
        for invalid in (dict(route, SEKVYR_TOKEN="forbidden"), dict(route, SEKVYR_URL="http://panel.example.invalid")):
            with self.assertRaises(RuntimeError):
                self.app.create_agent("bad", invalid, "agent-reader", {"name": "ca", "key": "ca.crt"})

    def test_mutations_have_uid_rv_tests_and_reject_identity_overwrite(self):
        self.app.owned.create_service_account("reader")
        self.app.owned.patch("ServiceAccount", "reader", [{"op": "add", "path": "/metadata/labels", "value": {"test": "yes"}}])
        operation = self.cluster.calls[-1][0]
        payload = json.loads(operation[operation.index("-p") + 1])
        self.assertEqual([item["path"] for item in payload[:2]], ["/metadata/uid", "/metadata/resourceVersion"])
        with self.assertRaises(RuntimeError):
            self.app.owned.patch("ServiceAccount", "reader", [{"op": "replace", "path": "/metadata", "value": {}}])

    def observed_status(self, current):
        pod = {"metadata": {"name": "app-pod", "namespace": "trial-apps", "uid": "old-pod", "ownerReferences": [
            {"kind": "ReplicaSet", "controller": True, "uid": "own-rs"}]},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
        status = {"generation": "one", "value_digest": "a" * 64, "boot_id": "1" * 8 + "-" + "1" * 4 + "-" + "1" * 4 + "-" + "1" * 4 + "-" + "1" * 12, "pid": 1}
        output = copy.deepcopy(pod) if current == "stable" else current
        def kube(*args, **kwargs):
            if args[:2] == ("get", "pods"):
                value = json.dumps({"items": [pod]})
            else:
                self.assertIn("--ignore-not-found", args)
                value = json.dumps(output) if output is not None else ""
            return SimpleNamespace(stdout=value)
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        module = SimpleNamespace(Forward=lambda *args: nullcontext(SimpleNamespace(port=1234)))
        response = SimpleNamespace(read=lambda limit: json.dumps(status).encode())
        opener = SimpleNamespace(open=lambda *args, **kwargs: nullcontext(response))
        with patch.object(self.app, "footprint", return_value={"replica_sets": ["own-rs"]}), patch.object(self.cluster, "kube", side_effect=kube), \
                patch("app_modes.importlib.util.spec_from_file_location", return_value=spec), patch("app_modes.importlib.util.module_from_spec", return_value=module), \
                patch("app_modes.urllib.request.build_opener", return_value=opener):
            return self.app.status("app")

    def test_status_discards_only_legitimate_rollout_transient_responses(self):
        self.assertEqual(self.observed_status("stable")["pod_uid"], "old-pod")
        self.assertFalse(self.observed_status(None))
        for meta in ({"uid": "old-pod", "deletionTimestamp": "synthetic-deletion"}, {"uid": "new-owned-pod"}):
            current = {"metadata": {"name": "app-pod", "namespace": "trial-apps", "ownerReferences": [
                {"kind": "ReplicaSet", "controller": True, "uid": "own-rs"}], **meta}}
            self.assertFalse(self.observed_status(current))

    def test_status_still_rejects_changed_owner_foreign_replacement_or_namespace(self):
        for uid in ("old-pod", "foreign-new-pod"):
            current = {"metadata": {"name": "app-pod", "namespace": "trial-apps", "uid": uid, "ownerReferences": [
                {"kind": "ReplicaSet", "controller": True, "uid": "foreign-rs"}]}}
            with self.assertRaises(RuntimeError):
                self.observed_status(current)
        current["metadata"]["namespace"] = "foreign"
        with self.assertRaises(RuntimeError):
            self.observed_status(current)


class ReaderGuards(unittest.TestCase):
    def setUp(self):
        self.before = dict(file_app.STATE)
        self.addCleanup(lambda: file_app.STATE.update(self.before))
        file_app.STATE.update(generation=None, value_digest=None, initial_loaded=False, reload_count=0, errors=0)

    def test_quoted_canaries_and_duplicate_rejection(self):
        self.assertEqual(file_app.assignments(b"GENERATION='one'\nDEMO_VALUE='two words\nnext'\n"), {"GENERATION": "one", "DEMO_VALUE": "two words\nnext"})
        for raw in (b"A=1 A=2", b"not-an-assignment", b"A='unterminated", b"A=\xff"):
            with self.assertRaises((ValueError, UnicodeError)):
                file_app.assignments(raw)

    def test_last_good_reload_and_error_preserve_boot(self):
        boot = file_app.STATE["boot_id"], file_app.STATE["pid"]
        with patch.object(file_app, "read_values", return_value={"GENERATION": "one", "DEMO_VALUE": "public-canary"}):
            file_app.poll("file")
            file_app.poll("file")
        self.assertEqual(file_app.STATE["reload_count"], 0)
        first = dict(file_app.STATE)
        with patch.object(file_app, "read_values", side_effect=OSError("unavailable")):
            file_app.poll("file")
        self.assertEqual(file_app.STATE["generation"], first["generation"])
        self.assertEqual(file_app.STATE["errors"], 1)
        with patch.object(file_app, "read_values", return_value={"GENERATION": "two", "DEMO_VALUE": "public-new"}):
            file_app.poll("volume")
        self.assertEqual(file_app.STATE["reload_count"], 1)
        self.assertEqual(file_app.STATE["value_digest"], hashlib.sha256(b"public-new").hexdigest())
        self.assertEqual((file_app.STATE["boot_id"], file_app.STATE["pid"]), boot)
        self.assertNotIn("DEMO_VALUE", json.dumps(file_app.STATE))

    def test_atomic_file_replace_reads_new_snapshot(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(file_app, "ROOT", Path(directory)):
            root = Path(directory)
            (root / ".env").write_bytes(b"GENERATION=one DEMO_VALUE=old")
            file_app.poll("file")
            (root / "replacement").write_bytes(b"GENERATION=two DEMO_VALUE=new")
            (root / "replacement").replace(root / ".env")
            file_app.poll("file")
            self.assertEqual(file_app.STATE["generation"], "two")
            self.assertEqual(file_app.STATE["reload_count"], 1)


if __name__ == "__main__":
    unittest.main()
