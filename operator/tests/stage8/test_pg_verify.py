"""Exercise the PG Job acceptance gates without a cluster or a real Secret."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from stage8 import pg_verify as pg


NS = "example-panel"
IMAGE = "example.invalid/verification@sha256:" + "a" * 64
AMD = "sha256:" + "b" * 64
LOG = "............... [100%]\n15 passed in 5.12s\n"


def resource(kind, name, namespace=NS, **fields):
    return {"apiVersion": "v1", "kind": kind, "metadata": {"name": name,
        "namespace": namespace, "uid": str(uuid.uuid4())}, **fields}


class FakeCluster:
    def __init__(self, task):
        self.task = task
        self.pins = task / "private" / "creation-uids"
        self.pins.mkdir(parents=True)
        self.fixture = {"namespaces": {"panel": NS}}
        self.namespaces = {NS}
        self.calls = []
        self.created = []
        self.panel_exists = False
        self.log = LOG
        self.replace_after_logs = False
        self.job_status = {"conditions": [{"type": "Complete", "status": "True"}], "succeeded": 1}
        self.objects = {}
        self.pin(resource("Namespace", NS, ""))
        db = resource("Deployment", "database", spec={"replicas": 1, "selector": {"matchLabels": {pg.LABEL: "database"}},
            "template": {"spec": {"containers": [{"name": "database", "env": [
                {"name": "POSTGRES_USER", "value": "trial_admin"}, {"name": "POSTGRES_PASSWORD_FILE", "value": "/access/password"}]}],
                "volumes": [{"name": "access", "secret": {"secretName": "database-access"}}]}}},
            status={"observedGeneration": 1, "readyReplicas": 1, "availableReplicas": 1})
        db["metadata"]["generation"] = 1
        self.pin(db)
        self.pin(resource("Service", "database", spec={"type": "ClusterIP", "clusterIP": "192.0.2.1",
            "selector": {pg.LABEL: "database"}, "ports": [{"protocol": "TCP", "port": 5432, "targetPort": 5432}]}))
        self.pin(resource("Secret", "database-access"))

    def pin(self, value):
        meta = value["metadata"]
        self.objects[value["kind"].lower(), meta["name"]] = value
        pin = {"kind": value["kind"], **{k: meta[k] for k in ("name", "namespace", "uid")}}
        (self.pins / (meta["uid"] + ".json")).write_text(json.dumps(pin))

    def namespace_pins(self):
        return {NS: self.objects["namespace", NS]["metadata"]["uid"]}

    def create(self, value):
        self.created.append(value)
        name, kind = value["metadata"]["name"], value["kind"]
        record = resource(kind, name, spec=copy.deepcopy(value["spec"]))
        self.pin(record)
        if kind == "Job":
            record["status"] = self.job_status
            pod = resource("Pod", name + "-pod", spec=copy.deepcopy(record["spec"]["template"]["spec"]), status={
                "phase": "Succeeded", "containerStatuses": [{"name": "pytest", "restartCount": 0,
                    "imageID": IMAGE.split("@")[0] + "@" + AMD, "state": {"terminated": {"exitCode": 0}}}]})
            pod["metadata"].update(labels={pg.LABEL: name}, ownerReferences=[{
                "apiVersion": "batch/v1", "kind": "Job", "name": name, "uid": record["metadata"]["uid"], "controller": True}])
            self.objects["pod", name + "-pod"] = pod
        return record

    def kube(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "wait":
            return SimpleNamespace(stdout="")
        if args[0] == "logs":
            if self.replace_after_logs:
                self.objects["pod", args[1]]["metadata"]["uid"] = str(uuid.uuid4())
            return SimpleNamespace(stdout=self.log)
        assert args[0] == "get"
        kind, name = args[1:3]
        if kind == "pods":
            value = {"items": [self.objects["pod", pg.NAME + "-pod"]]}
        elif (kind, name) == ("deployment", "panel"):
            return SimpleNamespace(stdout="deployment/panel" if self.panel_exists else "")
        elif kind == "secret":
            assert args[-1].startswith("jsonpath=") and ".data" not in args[-1]
            uid = self.objects[kind, name]["metadata"]["uid"]
            return SimpleNamespace(stdout=f"Secret|{NS}|{name}|{uid}|")
        else:
            value = self.objects[kind, name]
        return SimpleNamespace(stdout=json.dumps(value))


class PGVerificationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.cluster = FakeCluster(Path(temp.name))
        self.owner = SimpleNamespace(task=self.cluster.task, guard=lambda: None)
        (self.owner.task / "public-images-ready.json").write_text(json.dumps({"sourceStage": 8,
            "publicImagesImportedInsideCreationPinnedKind": 7, "hostDockerImageImports": 0,
            "newRCBinaryHashesVerified": True, "production": False}))
        self.directory = self.owner.task / "private" / pg.NAME

    def run_trial(self):
        with patch.object(pg.assets, "references", return_value={"tests": IMAGE}), \
                patch.object(pg, "Capability", return_value=self.owner), \
                patch.object(pg, "selected_manifest", return_value=(AMD, "sha256:" + "c" * 64)):
            return pg.run(self.cluster, profile="kind-1.37.0")

    def test_owned_job_controls_private_logs_and_exact_network(self):
        receipt = self.run_trial()
        self.assertEqual((receipt["passed"], receipt["skipped"]), (15, 0))
        self.assertEqual((self.directory / "pytest.log").read_text(), LOG)
        self.assertTrue((self.directory / "passed.json").is_file())
        ingress, egress, job = self.cluster.created
        for policy, direction, selector, peer in ((ingress, "ingress", "database", pg.NAME),
                (egress, "egress", pg.NAME, "database")):
            spec = policy["spec"]
            self.assertEqual(spec["podSelector"], {"matchLabels": {pg.LABEL: selector}})
            self.assertEqual(spec[direction], [{"from" if direction == "ingress" else "to": [
                {"podSelector": {"matchLabels": {pg.LABEL: peer}}}], "ports": [{"protocol": "TCP", "port": 5432}]}])
        pod = job["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["dnsPolicy"], "ClusterFirst")
        self.assertEqual(container["imagePullPolicy"], "Never")
        self.assertEqual(container["env"][0]["valueFrom"]["secretKeyRef"], {"name": "database-access", "key": "password"})
        self.assertIn("$(TRIAL_PG_PASSWORD)", container["env"][1]["value"])
        plugin = container["args"].index("pytest_asyncio.plugin")
        self.assertEqual(container["args"][plugin - 1], "-p")
        self.assertEqual(container["args"][-2:], ["tests/test_pg_migrations.py", "tests/test_pg_races.py"])
        self.assertTrue(all("postgresql+asyncpg" not in " ".join(args) for args in self.cluster.calls))

    def test_replaced_database_secret_or_existing_panel_prevents_mutations(self):
        self.cluster.panel_exists = True
        with self.assertRaisesRegex(RuntimeError, "precede panel"):
            self.run_trial()
        self.cluster.panel_exists = False
        self.cluster.objects["secret", "database-access"]["metadata"]["uid"] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, "Secret identity differs"):
            self.run_trial()
        self.assertEqual(self.cluster.created, [])

    def test_skips_or_failed_job_cannot_become_evidence(self):
        self.cluster.log = "14 passed, 1 skipped in 5.12s\n"
        with self.assertRaisesRegex(RuntimeError, "zero skips"):
            self.run_trial()
        self.assertTrue((self.directory / "pytest.log").exists())
        self.assertFalse((self.directory / "passed.json").exists())
        with self.assertRaisesRegex(RuntimeError, "Job did not complete"):
            pg.completed({"status": {"succeeded": 1}}, {}, IMAGE, AMD)

    def test_pod_replacement_during_log_read_never_persists_untrusted_log(self):
        self.cluster.replace_after_logs = True
        with self.assertRaisesRegex(RuntimeError, "replaced during log read"):
            self.run_trial()
        self.assertFalse((self.directory / "pytest.log").exists())

    def test_wrong_image_or_nonzero_exit_and_bounded_summary(self):
        self.run_trial()
        job = self.cluster.objects["job", pg.NAME]
        pod = self.cluster.objects["pod", pg.NAME + "-pod"]
        runtime = pod["status"]["containerStatuses"][0]
        runtime["imageID"] = IMAGE + "extra"
        with self.assertRaisesRegex(RuntimeError, "digest or exit"):
            pg.completed(job, pod, IMAGE, AMD)
        runtime["imageID"] = IMAGE
        runtime["state"]["terminated"]["exitCode"] = 1
        with self.assertRaisesRegex(RuntimeError, "digest or exit"):
            pg.completed(job, pod, IMAGE, AMD)
        with self.assertRaisesRegex(RuntimeError, "reached its bound"):
            pg.verify_summary(b"x" * (pg.MAX_LOG - len(LOG)) + LOG.encode())

    def test_generated_cri_name_needs_exact_archive_wrapper_and_root(self):
        root = IMAGE.split("@", 1)[1]
        def wrapper(image_root):
            return pg.canonical({"schemaVersion": 2, "mediaType": pg.archive_graph.INDEX,
                "manifests": [{"mediaType": pg.archive_graph.MANIFEST, "digest": image_root, "size": 321}]})
        raw = wrapper(root)
        digest = pg.archive_graph.sha(raw)
        prefix = "docker.io/library/import-2026-11-03@"
        owner = SimpleNamespace(exec=Mock(return_value=raw))
        self.assertEqual(pg.runtime_image_identity(prefix + digest, IMAGE, AMD, owner=owner, discovery=digest),
            "verifiedArchiveDiscoveryWrapper")
        owner.exec.assert_called_once_with("ctr", "-n", "k8s.io", "content", "get", digest)
        self.assertIsNone(pg.runtime_image_identity(prefix + AMD, IMAGE, AMD, owner=owner, discovery=digest))
        owner.exec.return_value = wrapper(AMD)
        wrong = pg.archive_graph.sha(owner.exec.return_value)
        with self.assertRaisesRegex(RuntimeError, "another image"):
            pg.runtime_image_identity(prefix + wrong, IMAGE, AMD, owner=owner, discovery=wrong)


if __name__ == "__main__":
    unittest.main()
