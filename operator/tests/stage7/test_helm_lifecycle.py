"""UID/scope/lifecycle guards with a fake API and optional real Helm render."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from app_modes import resource
from helm_lifecycle import HelmLifecycle, canonical, identity, normalization_input, private_exact
from test_app_modes import FakeCluster


class HelmCluster(FakeCluster):
    config = Path("explicit-kubeconfig")

    def __init__(self, root):
        super().__init__(root)
        (self.task / "private").mkdir()
        self.receipts, self.captures, self.reviews = [], [], []

    def persist_helm_preflight(self, receipt):
        for item in receipt["absent"]:
            if (item["kind"], item["name"]) in self.objects:
                raise RuntimeError("Existing managed name cannot be adopted")
        self.receipts.append(copy.deepcopy(receipt))
        return receipt

    def capture_helm_created(self, current, manifest, release, receipt):
        if receipt not in self.receipts:
            raise AssertionError("Capture before durable preflight")
        self.captures.append(copy.deepcopy(current))

    def review_cluster_manifests(self, manifests):
        self.reviews.extend(copy.deepcopy(manifests))

    def kube(self, *args, **kwargs):
        if args[0] == "replace" and "--dry-run=server" in args:
            return subprocess.CompletedProcess(args, 0, stdout=kwargs["data"], stderr="")
        if args[0] == "get" and args[1] != "namespace":
            key = args[1], args[2]
            if key not in self.objects and "--ignore-not-found" in args:
                return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        return super().kube(*args, **kwargs)


class LifecycleGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.cluster = HelmCluster(root)
        self.helm = root / "helm"
        self.helm.write_text("fixture", encoding="utf-8")
        self.chart = root / "chart"
        self.chart.mkdir()
        (self.chart / "Chart.yaml").write_text("name: fixture", encoding="utf-8")
        self.helper = HelmLifecycle(self.cluster, self.helm, self.chart, "trial", "trial-apps")

    def manifest(self, name="config-one", data="one"):
        value = resource("ConfigMap", name, "trial-apps")
        value.update(immutable=True, data={"installation.json": data})
        value["metadata"]["annotations"] = {"helm.sh/resource-policy": "keep"}
        return value

    def put(self, value):
        current = copy.deepcopy(value)
        current["metadata"].update(uid="helm-" + value["metadata"]["name"], resourceVersion="1")
        current["metadata"].setdefault("annotations", {}).update({"meta.helm.sh/release-name": "trial", "meta.helm.sh/release-namespace": "trial-apps"})
        current["metadata"].setdefault("labels", {})["app.kubernetes.io/managed-by"] = "Helm"
        self.cluster.objects[(current["kind"], current["metadata"]["name"])] = current

    def install_fake(self, manifests):
        with patch.object(self.helper, "_run", return_value=subprocess.CompletedProcess([], 0, stdout="[]")):
            receipt, new = self.helper._preflight(manifests, "install")
        for value in manifests:
            self.put(value)
        self.assertTrue(self.helper._capture(manifests, new, receipt))
        return receipt

    def test_install_captures_only_after_exclusive_preflight(self):
        receipt = self.install_fake([self.manifest()])
        self.assertEqual(receipt["namespaceUID"], "namespace-own")
        self.assertEqual(len(self.cluster.captures), 1)
        self.assertEqual(self.cluster.captures[0]["metadata"]["uid"], "helm-config-one")
        with self.assertRaises(RuntimeError):
            self.helper._preflight([self.manifest()], "install")

    def test_preexisting_name_not_adopted(self):
        self.put(self.manifest())
        with patch.object(self.helper, "_run", return_value=subprocess.CompletedProcess([], 0, stdout="[]")), self.assertRaises(RuntimeError):
            self.helper._preflight([self.manifest()], "install")
        self.assertFalse(self.cluster.captures)

    def test_uid_change_blocks_upgrade(self):
        self.install_fake([self.manifest()])
        self.cluster.objects[("ConfigMap", "config-one")]["metadata"]["uid"] = "replacement"
        with self.assertRaises(RuntimeError):
            self.helper._preflight([self.manifest("config-two")], "upgrade")

    def test_upgrade_retains_old_revision_and_uninstall_preserves_both(self):
        old, new = self.manifest(), self.manifest("config-two", "two")
        self.install_fake([old])
        receipt, pending = self.helper._preflight([new], "upgrade")
        self.put(new)
        self.helper._capture([new], pending, receipt)
        self.assertEqual(len(self.helper.retained), 1)
        with patch.object(self.helper, "_run", return_value=subprocess.CompletedProcess([], 0)):
            result = self.helper.uninstall()
        self.assertTrue(result["helmUninstalled"])
        self.assertEqual(result["retainedRevisions"], 2)
        self.assertEqual(len(self.cluster.objects), 2)

    def test_old_retained_revision_tamper_blocks_later_operation(self):
        old, new = self.manifest(), self.manifest("config-two", "two")
        self.install_fake([old])
        receipt, pending = self.helper._preflight([new], "upgrade")
        self.put(new)
        self.helper._capture([new], pending, receipt)
        self.cluster.objects[("ConfigMap", "config-one")]["data"] = {"installation.json": "tampered"}
        with self.assertRaises(RuntimeError):
            self.helper.uninstall()

    def test_post_helm_wrong_content_cannot_pass_as_success(self):
        desired = self.manifest()
        with patch.object(self.helper, "_run", return_value=subprocess.CompletedProcess([], 0, stdout="[]")):
            receipt, new = self.helper._preflight([desired], "install")
        self.put(self.manifest(data="unreviewed"))
        with self.assertRaisesRegex(RuntimeError, "normalized manifest"):
            self.helper._capture([desired], new, receipt)

    def test_normalization_preserves_only_runtime_lease_and_service_allocations(self):
        lease = resource("Lease", "lock", "trial-apps", {}, "coordination.k8s.io/v1")
        actual = copy.deepcopy(lease)
        actual["metadata"].update(uid="own", resourceVersion="2")
        actual["spec"] = {"holderIdentity": "own-process", "leaseTransitions": 2}
        self.assertEqual(normalization_input(lease, actual)["spec"], actual["spec"])
        actual["spec"]["foreign"] = True
        with self.assertRaises(RuntimeError):
            normalization_input(lease, actual)
        service = resource("Service", "fencer", "trial-apps", {"selector": {"role": "own"}, "ports": [{"port": 9443}]})
        actual = copy.deepcopy(service)
        actual["metadata"].update(uid="own", resourceVersion="2")
        actual["spec"].update(clusterIP="192.0.2.10", selector={"role": "foreign"})
        desired = normalization_input(service, actual)
        self.assertEqual(desired["spec"]["clusterIP"], "192.0.2.10")
        self.assertEqual(desired["spec"]["selector"], {"role": "own"})

    def test_render_rejects_foreign_scope_external_identity_and_hooks(self):
        for invalid in (dict(self.manifest(), kind="Secret"), resource("ConfigMap", "other", "foreign")):
            with patch.object(self.helper, "_run", return_value=subprocess.CompletedProcess([], 0, stdout=yaml.safe_dump(invalid))):
                with self.assertRaises(RuntimeError):
                    self.helper.render({})
        hooked = self.manifest()
        hooked["metadata"]["annotations"]["helm.sh/hook"] = "pre-install"
        with patch.object(self.helper, "_run", return_value=subprocess.CompletedProcess([], 0, stdout=yaml.safe_dump(hooked))):
            with self.assertRaises(RuntimeError):
                self.helper.render({})

    def test_external_creation_pin_and_no_release_ownership(self):
        sa = self.cluster.create(dict(resource("ServiceAccount", "reader", "trial-apps"), automountServiceAccountToken=False))
        pins = [{"kind": "ServiceAccount", "name": "reader", "uid": sa["metadata"]["uid"]}]
        helper = HelmLifecycle(self.cluster, self.helm, self.chart, "other", "trial-apps", pins)
        with patch.object(helper, "_run", return_value=subprocess.CompletedProcess([], 0, stdout=yaml.safe_dump(resource("ServiceAccount", "reader", "trial-apps")))):
            with self.assertRaises(RuntimeError):
                helper.render({})
        self.cluster.objects[("ServiceAccount", "reader")]["metadata"]["uid"] = "replacement"
        with self.assertRaises(RuntimeError):
            helper._external_guard()

    def test_private_inputs_exact_resume_and_errors_redacted(self):
        path = self.helper.directory / "review.json"
        private_exact(path, b"one")
        private_exact(path, b"one")
        with self.assertRaises(RuntimeError):
            private_exact(path, b"two")
        with patch("helm_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 1, stderr="untrusted-secret")):
            with self.assertRaisesRegex(RuntimeError, "^Scoped Helm operation failed$"):
                self.helper._run("list")

    def test_helm_argv_scopes_kubeconfig_and_namespace(self):
        with patch("helm_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="[]")) as run:
            self.helper._run("list")
        args = run.call_args.args[0]
        self.assertEqual(args[-4:], ["--kubeconfig", str(self.cluster.config), "--namespace", "trial-apps"])
        self.assertNotIn("--take-ownership", args)
        self.assertNotIn("--force", args)


@unittest.skipUnless(os.environ.get("HELM_BIN"), "Exact Helm executable required")
class RealRender(unittest.TestCase):
    def test_pinned_helm_parses_generated_lifecycle_argv_without_api_mutation(self):
        helm = os.environ["HELM_BIN"]
        version = subprocess.run([helm, "version", "--short"], capture_output=True, text=True, timeout=10)
        self.assertEqual(version.returncode, 0)
        self.assertTrue(version.stdout.startswith("v4.3.1+"))
        # A real parser negative proves --help does not hide unknown flags.
        old = subprocess.run([helm, "list", "--all", "--help"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn("unknown flag", old.stderr.lower())
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            cluster = HelmCluster(directory)
            helper = HelmLifecycle(cluster, helm, root / "charts" / "sekvyr-operator", "trial", "trial-apps")
            observed = []
            def checked(*args, check=True):
                observed.append(args)
                result = subprocess.run([helm, *args, "--kubeconfig", str(cluster.config), "--namespace", "trial-apps", "--help"],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, "Pinned Helm rejected generated lifecycle arguments")
                if args[0] == "list":
                    self.assertIn("all releases in any status", result.stdout)
                    self.assertNotIn("--all", args)
                    return subprocess.CompletedProcess(args, 0, stdout="[]")
                return subprocess.CompletedProcess(args, 0, stdout="")
            with patch.object(helper, "_run", side_effect=checked):
                helper._preflight([], "install")
                path = Path(directory) / "values.json"
                path.write_text("{}", encoding="utf-8")
                with patch.object(helper, "render", return_value=([], path)), patch.object(helper, "_preflight", return_value=({}, [])), patch.object(helper, "_capture", return_value=True):
                    helper.install({})
                    helper.upgrade({})
                manifest = resource("Role", "owned-role", "trial-apps")
                current = copy.deepcopy(manifest)
                current["metadata"].update(uid="owned-role-uid", resourceVersion="1", annotations={
                    "meta.helm.sh/release-name": "trial", "meta.helm.sh/release-namespace": "trial-apps"},
                    labels={"app.kubernetes.io/managed-by": "Helm"})
                helper.managed = {identity(manifest): {"manifest": manifest, "uid": "owned-role-uid", "data": None}}
                with patch.object(helper, "_get", side_effect=[current, None]), patch.object(helper, "_matches"):
                    helper.uninstall()
            self.assertEqual([args[0] for args in observed], ["list", "install", "upgrade", "uninstall"])

    def test_template_two_versions_is_only_render_evidence(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            cluster = HelmCluster(directory)
            helper = HelmLifecycle(cluster, os.environ["HELM_BIN"], root / "charts" / "sekvyr-operator", "trial", "trial-apps")
            values = yaml.safe_load((root / "tests" / "chart" / "values.public.example.yaml").read_text(encoding="utf-8"))
            values["installation"]["namespace"] = "trial-apps"
            for version in ("1.34.1", "1.37.0"):
                rendered, _ = helper.render(values, version)
                self.assertTrue(any(value["kind"] == "Deployment" for value in rendered))
                self.assertFalse(any(value["kind"] in ("CustomResourceDefinition", "Secret") for value in rendered))


if __name__ == "__main__":
    unittest.main()
