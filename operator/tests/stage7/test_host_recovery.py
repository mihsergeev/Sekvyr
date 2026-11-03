"""Local guard tests only; no remote calls, root process or Kubernetes writes."""

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

import host_recovery as recovery
from helm_lifecycle import canonical
from recovery_process import RecoveryProcessError
import test_kind_recovery as fixtures


class RemoteTask:
    # Keep test files on the local test filesystem while modeling only the
    # parent identity. The production safe_task guard is not changed.
    parent = Path("/opt/sekvyr-trial")
    def __init__(self, directory): self.directory = Path(directory).resolve()
    def __truediv__(self, part): return self.directory / part
    def __str__(self): return "/opt/sekvyr-trial/sekvyr-stage7-20261102-00000001"


class HostGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.task = RemoteTask(self.temp.name)
        (self.task / "private").mkdir()
        self.config = self.task / "kubeconfig"
        self.raw = yaml.safe_dump(fixtures.configs()).encode()
        self.config.write_bytes(self.raw)
        self.config.chmod(0o600)
        (self.task / "infrastructure-parameters.json").write_bytes(canonical({"expected_kubernetes": recovery.REMOTE_VERSION}))
        self.pins = {"trial-" + role: "public-synthetic-uid-" + role for role in ("apps", "panel", "witness", "gateway", "storage", "isolation")}
        self.guards = []
        self.version = recovery.REMOTE_VERSION
        self.cluster = SimpleNamespace(task=self.task, config=self.config, namespaces=set(self.pins),
            namespace_pins=lambda: copy.deepcopy(self.pins), kube=lambda *args: SimpleNamespace(stdout=json.dumps({"serverVersion": {"gitVersion": self.version}})))
        self.panel = SimpleNamespace(task=self.task, cluster=self.cluster, namespace="trial-panel")
        self.addCleanup(patch.stopall)
        if os.name == "nt":
            # NTFS chmod does not expose POSIX group/other mode bits. Production
            # executes on Linux; model its private mode for these local guards.
            patch.object(recovery.stat, "S_IMODE", return_value=0o600).start()
            remove = recovery.shutil.rmtree
            def remove_windows_fixture(path, *args, **kwargs):
                # Windows makes the Linux 0500 test binary read-only. Relax only
                # files in this exact already-validated temporary sandbox.
                candidate = Path(path).resolve()
                if candidate.parent == self.task / "private" and candidate.name.startswith("host-recovery-"):
                    for child in candidate.rglob("*"):
                        if child.is_file() and not child.is_symlink(): child.chmod(0o600)
                return remove(path, *args, **kwargs)
            patch.object(recovery.shutil, "rmtree", side_effect=remove_windows_fixture).start()
        patch.object(recovery, "safe_task", side_effect=lambda task: task).start()
        patch.object(recovery, "OwnedNamespace", side_effect=lambda cluster, namespace: SimpleNamespace(guard=lambda: self.guards.append(namespace))).start()

    def test_original_tls_config_and_all_six_uid_scopes_preserved(self):
        raw, pin, path = recovery.host_pin(self.panel)
        self.assertEqual(raw, self.raw)
        self.assertEqual(self.config.read_bytes(), self.raw)
        self.assertEqual(pin["namespaceUIDs"], self.pins)
        self.assertEqual(pin["kubeconfigSHA256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(self.guards, sorted(self.pins))
        self.assertEqual(json.loads(path.read_bytes()), pin)

    def test_live_version_foreign_scope_or_changed_config_is_rejected(self):
        recovery.host_pin(self.panel)
        self.version = "v1.35.0"
        with self.assertRaisesRegex(RuntimeError, "live Kubernetes version"):
            recovery.host_pin(self.panel)
        self.version = recovery.REMOTE_VERSION
        self.pins.pop("trial-storage")
        with self.assertRaisesRegex(RuntimeError, "six owned"):
            recovery.host_pin(self.panel)
        self.pins["trial-storage"] = "public-synthetic-uid-storage"
        self.config.write_bytes(yaml.safe_dump(fixtures.configs()).encode())
        with self.assertRaisesRegex(RuntimeError, "changed on resume"):
            recovery.host_pin(self.panel)

    def test_config_proxy_exec_or_tls_downgrade_never_reaches_supervisor(self):
        value = yaml.safe_load(self.raw)
        value["clusters"][0]["cluster"]["proxy-url"] = "https://proxy.example.invalid"
        self.config.write_bytes(yaml.safe_dump(value).encode())
        with patch.object(recovery, "run_recovery") as run:
            with self.assertRaises(RuntimeError):
                recovery.recover(self.panel, {}, {}, {}, {})
        run.assert_not_called()

    def run_adapter(self, error=None):
        pin_path = self.task / "private" / "host-recovery-pin.json"
        pin = {"kubeconfigSHA256": hashlib.sha256(self.raw).hexdigest(), "namespaceUIDs": self.pins}
        pin_path.write_bytes(canonical(pin))
        captured = {}
        def run(path, raw, profile):
            self.assertEqual(profile, "host")
            plan = json.loads(raw)
            sandbox = path.parent
            self.assertEqual((sandbox / "inputs" / "kubeconfig").read_bytes(), self.raw)
            self.assertEqual((sandbox / "etc" / "resolv.conf").read_bytes(), b"nameserver 192.0.2.53\n")
            self.assertEqual(set(plan).intersection({"cid", "pid", "starttime"}), set())
            captured["sandbox"] = sandbox
            captured["plan"] = plan
            if error is not None: raise error
            return {"checkpointRecoveryComplete": True, "terminationConfirmed": True}
        with patch.object(recovery, "host_pin", return_value=(self.raw, pin, pin_path)), \
                patch.object(recovery, "verified_cli", return_value=b"PUBLIC_SYNTHETIC_ELF_PLACEHOLDER"), \
                patch.object(recovery, "database_resolver", return_value=b"nameserver 192.0.2.53\n"), \
                patch.object(recovery, "run_recovery", side_effect=run):
            if error is None:
                result = recovery.recover(self.panel, {"body": {"allow_rollout": False}}, {}, {}, {"namespace": "trial-apps", "ha": {}})
                self.assertTrue(result["terminationConfirmed"])
            else:
                with self.assertRaises(RecoveryProcessError) as caught:
                    recovery.recover(self.panel, {"body": {"allow_rollout": False}}, {}, {}, {"namespace": "trial-apps", "ha": {}})
                self.assertEqual(caught.exception.termination_confirmed, error.termination_confirmed)
        return captured

    def test_child_only_private_dns_and_confirmed_cleanup(self):
        captured = self.run_adapter()
        self.assertFalse(captured["sandbox"].exists())
        self.assertEqual(self.config.read_bytes(), self.raw)

    def test_unconfirmed_child_preserves_private_inputs_and_typed_error(self):
        captured = self.run_adapter(RecoveryProcessError(False))
        self.assertTrue((captured["sandbox"] / "inputs" / "kubeconfig").is_file())

    def test_confirmed_rejection_cleans_only_own_sandbox(self):
        captured = self.run_adapter(RecoveryProcessError(True))
        self.assertFalse(captured["sandbox"].exists())

    def test_cleanup_rejects_inode_replacement_and_retains_unknown(self):
        directory = self.task / "private" / ("host-recovery-" + "a" * 32)
        directory.mkdir()
        info = directory.stat()
        self.assertFalse(recovery.cleanup_sandbox(self.task, directory, (info.st_dev, info.st_ino), False))
        with self.assertRaisesRegex(RuntimeError, "identity"):
            recovery.cleanup_sandbox(self.task, directory, (info.st_dev, info.st_ino + 1), True)
        self.assertTrue(directory.exists())

    def test_public_error_never_quotes_private_parser_input(self):
        canary = "PUBLIC_SYNTHETIC_SECRET_ERROR_CANARY"
        with patch.object(recovery, "_recover", side_effect=ValueError(canary)):
            try: recovery.recover(None, None, None, None, None)
            except RuntimeError as error:
                self.assertNotIn(canary, "".join(traceback.format_exception(error)))
            else: self.fail("Parser failure was accepted")


if __name__ == "__main__":
    unittest.main()
