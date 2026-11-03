"""Remote kind creator/identity/profile guards. No Docker, sudo or setns runs."""

import ast
import copy
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fixture import canonical
import kind_recovery
import remote_kind_capability as cap
import remote_kind_recovery as recovery
from remote_kind_jwks import RemoteKindJWKS
import prepare_remote_kind as creator
import recovery_process


def fixture_file_uid(executable, uid):
    """Change metadata ONLY for this exact synthetic file, never production."""
    original = Path.stat
    def metadata(path, *args, **kwargs):
        actual = original(path, *args, **kwargs)
        if path != executable:
            return actual
        fields = list(actual)
        fields[4] = uid
        return os.stat_result(fields)
    return patch.object(Path, "stat", metadata)


class CapabilityGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.root, self.task = base / "root", base / "sekvyr-stage7.deadbeef"
        self.backup = self.root / "private" / "creator"
        self.backup.mkdir(parents=True)
        (self.task / "private").mkdir(parents=True)
        self.host = {"bootID": "11111111-1111-4111-8111-111111111111", "daemonIDHash": "a" * 64}
        self.process = {"pid": 123, "starttime": "987"}
        self.directories = [{"path": str(value), "uid": 0, "dev": 1, "ino": index} for index, value in enumerate((self.root, self.task, self.backup), 10)]
        self.cluster_name = "sekvyr-stage7-deadbeef"
        self.fixture = {"format": "sekvyr-stage7-fixture-v1", "production": False,
            "namespaces": {role: self.cluster_name + "-" + role for role in cap.ROLES}}
        self.cluster = SimpleNamespace(task=self.task, fixture=self.fixture)
        self.node = {"Id": "1" * 64, "Name": "/" + self.cluster_name + "-control-plane", "Image": "sha256:" + "2" * 64,
            "Config": {"Image": cap.NODE, "Labels": {"io.x-k8s.kind.cluster": self.cluster_name, "io.x-k8s.kind.role": "control-plane"}},
            "HostConfig": dict(cap.CAPS), "State": {"Running": True, "Pid": 123}, "Mounts": [{"Type": "volume", "Name": "owned-anonymous"}],
            "NetworkSettings": {"Networks": {"kind": {"NetworkID": "3" * 64}}}}
        self.network = {"Id": "3" * 64, "Name": "kind", "Driver": "bridge", "Containers": {self.node["Id"]: {"Name": "own"}}}
        repository = cap.NODE.split("@", 1)[0].rsplit(":", 1)[0] + "@" + cap.NODE.split("@", 1)[1]
        self.image = [{"Id": self.node["Image"], "RepoDigests": [repository]}]
        self.preflight = {"format": "sekvyr-stage7-remote-kind-preflight-v1", "rootTask": str(self.root), "runtimeTask": str(self.task),
            "clusterName": self.cluster_name, "nodeImage": cap.NODE, "limits": cap.CAPS, "host": copy.deepcopy(self.host),
            "directories": copy.deepcopy(self.directories), "baseline": {"containers": {"f" * 64: {}}, "networks": {}, "volumes": {}, "kindNetwork": None},
            "rootCreationReceiptSHA256": cap.digest(b"independent-create-receipt")}
        self.created = {"format": "sekvyr-stage7-remote-kind-created-v1", "preflightSHA256": cap.digest(canonical(self.preflight)),
            "node": {"id": self.node["Id"], "image": cap.NODE, "volumes": ["owned-anonymous"]}, "nodeOCIImageID": self.node["Image"],
            "nodeName": self.node["Name"], "configSHA256": cap.digest(canonical(self.node["Config"])), "mountsSHA256": cap.digest(canonical(self.node["Mounts"])),
            "process": copy.deepcopy(self.process), "fixture": copy.deepcopy(self.fixture),
            "network": {"id": self.network["Id"], "configSHA256": cap.network_hash(self.network), "created": True}, "volumeSHA256": {}}
        self.limits = {"format": "sekvyr-stage7-remote-kind-caps-v1", "creatorSHA256": cap.digest(canonical(self.created)),
            "limits": cap.CAPS, "hostConfigSHA256": cap.digest(canonical(self.node["HostConfig"]))}
        marker = {"format": cap.FORMAT, "rootTask": str(self.root), "runtimeTask": str(self.task),
            "preflightSHA256": cap.digest(canonical(self.preflight)), "creatorSHA256": cap.digest(canonical(self.created)), "capsSHA256": cap.digest(canonical(self.limits))}
        for path, value in ((self.task / "private" / cap.MARKER, marker), (self.task / "private" / "node-pin.json", self.created["node"]),
                (self.backup / "preflight.json", self.preflight), (self.backup / "creation.json", self.created), (self.backup / "caps.json", self.limits)):
            path.write_bytes(canonical(value))
        self.calls = []
        for replacement in (patch.object(cap, "read", side_effect=lambda path, *args: (Path(path).read_bytes(), json.loads(Path(path).read_bytes()))),
                patch.object(cap, "paths", return_value=(self.root, self.task, self.backup)),
                patch.object(cap, "root_creation", return_value=(b"independent-create-receipt", {})),
                patch.object(cap, "directory", side_effect=lambda path: copy.deepcopy(next(value for value in self.directories if value["path"] == str(path)))),
                patch.object(cap, "host", side_effect=lambda: copy.deepcopy(self.host)), patch.object(cap, "process", side_effect=lambda pid: copy.deepcopy(self.process)),
                patch.object(cap, "docker", side_effect=self.docker)):
            replacement.start()
            self.addCleanup(replacement.stop)

    def docker(self, *args, **kwargs):
        self.calls.append(args)
        if args == ("inspect", self.node["Id"]): return canonical([self.node])
        if args == ("image", "inspect", cap.NODE): return canonical(self.image)
        if args == ("network", "inspect", self.network["Id"]): return canonical([self.network])
        if args[0] == "exec": return b"safe-result"
        raise AssertionError("Unexpected fake operation")

    def test_complete_creator_chain_allows_only_exact_owned_exec(self):
        owner = cap.Capability(self.cluster)
        self.assertEqual(owner.exec("true"), b"safe-result")
        self.assertEqual(self.calls[-1], ("exec", self.node["Id"], "true"))

    def test_caps_or_other_hostconfig_changes_block_before_exec(self):
        owner = cap.Capability(self.cluster)
        self.node["HostConfig"]["Memory"] += 1
        with self.assertRaises(RuntimeError): owner.exec("true")
        self.assertNotEqual(self.calls[-1][0], "exec")

    def test_wrong_oci_digest_or_alias_is_never_adopted(self):
        self.image[0]["RepoDigests"] = ["example.invalid/other@sha256:" + "f" * 64]
        with self.assertRaisesRegex(RuntimeError, "OCI"): cap.Capability(self.cluster)

    def test_same_name_replacement_cid_or_kind_label_is_not_creator(self):
        self.node["Config"]["Labels"]["io.x-k8s.kind.cluster"] = "foreign"
        with self.assertRaisesRegex(RuntimeError, "identity"): cap.Capability(self.cluster)

    def test_restarted_node_pid_starttime_requires_new_explicit_review(self):
        self.process["starttime"] = "reused-pid"
        with self.assertRaisesRegex(RuntimeError, "starttime"): cap.Capability(self.cluster)

    def test_other_host_or_daemon_refuses_exact_reused_receipts(self):
        self.host["daemonIDHash"] = "b" * 64
        with self.assertRaisesRegex(RuntimeError, "host/daemon"): cap.Capability(self.cluster)

    def test_directory_inode_replacement_and_receipt_mutation_are_not_adopted(self):
        self.directories[0]["ino"] += 1
        with self.assertRaisesRegex(RuntimeError, "directory identity"): cap.Capability(self.cluster)

    def test_shared_network_refuses_any_owned_exec(self):
        self.network["Containers"]["f" * 64] = {"Name": "foreign"}
        with self.assertRaisesRegex(RuntimeError, "shared"): cap.Capability(self.cluster)

    def test_capability_marker_change_after_construction_is_rejected(self):
        owner = cap.Capability(self.cluster)
        marker = json.loads(owner.marker.read_bytes())
        marker["format"] = "another-provider"
        owner.marker.write_bytes(canonical(marker))
        with self.assertRaisesRegex(RuntimeError, "capability changed"): owner.guard()

    def test_independent_receipt_is_not_derived_from_runtime_pin(self):
        (self.backup / "creation.json").write_bytes(canonical({"node": self.created["node"]}))
        with self.assertRaises((RuntimeError, KeyError)): cap.Capability(self.cluster)

    def test_remote_jwks_has_exact_external_backup_and_no_native_windows_path(self):
        with patch("remote_kind_jwks.Capability", return_value=cap.Capability(self.cluster)):
            signer = RemoteKindJWKS(self.cluster, self.task / "private" / cap.MARKER)
            self.assertEqual(signer.native, self.backup)
            self.assertEqual(signer.creation_receipt, self.backup / "creation.json")
            self.assertFalse(signer.prepared)
            self.assertEqual(signer._exec("true"), b"safe-result")

    def test_creator_dry_cleanup_cannot_delete_foreign_network_or_container(self):
        owner = cap.Capability(self.cluster)
        with patch.object(creator, "foreign_unchanged"), patch.object(creator, "docker", side_effect=AssertionError("Must not mutate")):
            result = creator.cleanup(owner, execute=False)
        self.assertFalse(result["deleteRequested"])


class RemoteRecoveryGuards(unittest.TestCase):
    def test_profile_is_fixed_and_uses_identical_network_fd_algorithm(self):
        code = recovery_process.driver_source("remote-kind")
        ast.parse(code)
        self.assertIn(kind_recovery.NET_JOIN, code)
        self.assertIn(recovery.CLI_SHA256, code)
        self.assertIn(cap.NODE, code)
        self.assertIn("threading.Thread(target=watchdog,daemon=True).start()", code)
        with self.assertRaises(recovery_process.RecoveryProcessError): recovery_process.driver_source("arbitrary-module")

    def test_explicit_bad_remote_marker_never_falls_back_to_wsl_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "private").mkdir()
            (task / "private" / cap.MARKER).write_bytes(b"bad")
            with patch.object(kind_recovery, "_recover") as old, patch.object(recovery, "_recover", side_effect=RuntimeError("SYNTHETIC_PRIVATE_VALUE")):
                with self.assertRaises(RuntimeError) as failure: kind_recovery.recover(SimpleNamespace(task=task), {}, b"", b"", {})
            old.assert_not_called()
            self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", str(failure.exception))

    def test_fixed_new_cli_hash_and_loader_checks_do_not_change_old_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "tools").mkdir()
            executable = task / "tools" / "sekvyr-checkpoint-recovery"
            raw = bytearray(120)
            raw[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", raw, 18, 62); struct.pack_into("<Q", raw, 32, 64)
            struct.pack_into("<H", raw, 54, 56); struct.pack_into("<H", raw, 56, 1)
            executable.write_bytes(raw)
            proof = {"image": "example.invalid/operator@" + recovery.IMAGE_DIGEST, "sha256": cap.digest(raw)}
            panel = SimpleNamespace(task=task, recovery_executable=executable)
            with fixture_file_uid(executable, 0), patch.object(recovery, "read", return_value=(b"", proof)), patch.object(recovery, "CLI_SHA256", cap.digest(raw)):
                self.assertEqual(recovery.verified_cli(panel), raw)
                executable.write_bytes(raw + b"tamper")
                with self.assertRaises(RuntimeError): recovery.verified_cli(panel)
            struct.pack_into("<I", raw, 64, 3)  # PT_INTERP: exact hash is insufficient.
            executable.write_bytes(raw)
            proof["sha256"] = cap.digest(raw)
            with fixture_file_uid(executable, 0), patch.object(recovery, "read", return_value=(b"", proof)), patch.object(recovery, "CLI_SHA256", cap.digest(raw)):
                with self.assertRaisesRegex(RuntimeError, "dynamic loader"): recovery.verified_cli(panel)
            self.assertNotEqual(kind_recovery.CLI_SHA256, recovery.CLI_SHA256)

    def test_nonroot_cli_file_is_rejected_before_proof_or_hash_processing(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "tools").mkdir()
            executable = task / "tools" / "sekvyr-checkpoint-recovery"
            executable.write_bytes(b"synthetic-unprivileged-file")
            panel = SimpleNamespace(task=task, recovery_executable=executable)
            with fixture_file_uid(executable, 1001), patch.object(recovery, "read") as proof:
                with self.assertRaisesRegex(RuntimeError, "executable required"): recovery.verified_cli(panel)
            proof.assert_not_called()

    def test_remote_recovery_preserves_only_safe_cancel_termination_fact(self):
        for confirmed in (True, False):
            error = RuntimeError("SYNTHETIC_PRIVATE_VALUE")
            error.termination_confirmed = confirmed
            with patch.object(recovery, "_recover", side_effect=error):
                with self.assertRaises(RuntimeError) as failure: recovery.recover(None, None, None, None, None)
            self.assertIs(failure.exception.termination_confirmed, confirmed)
            self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", str(failure.exception))

    def test_root_setup_contains_no_user_selected_source_import_or_host_config_write(self):
        ast.parse(recovery.ROOT_SETUP)
        self.assertNotIn("/etc/resolv.conf", recovery.ROOT_SETUP)
        self.assertNotIn("setns(fd,os.CLONE_NEWNS)", recovery.ROOT_SETUP)
        self.assertIn("rootCreationReceiptSHA256", recovery.ROOT_SETUP)

    def test_remote_directory_shape_does_not_expand_old_wsl_native_backup_validator(self):
        from kind_jwks import native_path
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError): native_path(Path(directory))

    def test_cancelled_supervisor_retains_inputs_until_termination_is_confirmed(self):
        for confirmed in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                task = Path(directory)
                (task / "private").mkdir()
                owner = SimpleNamespace(task=task, exec=Mock(return_value=b"own-admin"), guard=Mock(),
                    root_plan=lambda: {}, creator={"process": {"pid": 123, "starttime": "pinned"}})
                panel = SimpleNamespace(task=task, cluster=SimpleNamespace(namespaces={"trial-apps"}, config=task / "kubeconfig"))
                panel.cluster.config.write_bytes(b"synthetic-private-config")
                failure = recovery_process.RecoveryProcessError(confirmed)
                with patch.object(recovery, "Capability", return_value=owner), patch.object(recovery, "verified_cli", return_value=b"static"),\
                        patch.object(recovery, "recovery_kubeconfig", return_value=b"private"), patch.object(recovery, "database_resolver", return_value=b"nameserver 192.0.2.53\n"),\
                        patch.object(recovery, "run_recovery", side_effect=failure), patch.object(recovery, "cleanup_sandbox") as cleanup:
                    with self.assertRaises(recovery_process.RecoveryProcessError):
                        recovery._recover(panel, {"body": {"allow_rollout": False}}, b"ciphertext", b"wrap", {"namespace": "trial-apps", "ha": {"trial": True}})
                self.assertIs(cleanup.call_args.args[-1], confirmed)


class CreatorGuards(unittest.TestCase):
    def test_missing_runtime_capability_aborts_before_any_directory_or_docker_action(self):
        with patch.object(creator.os, "geteuid", return_value=0, create=True), patch.object(creator.os, "uname", return_value=SimpleNamespace(sysname="Linux", machine="x86_64"), create=True),\
                patch.object(creator, "runtime_capabilities", side_effect=RuntimeError("missing")), patch.object(creator, "paths") as paths, patch.object(creator, "docker") as docker:
            with self.assertRaisesRegex(RuntimeError, "missing"):
                creator.create("root", "runtime", "kind", "helm", "kubectl", "a", "b", "c", "crds")
        paths.assert_not_called()
        docker.assert_not_called()

    def test_existing_root_requires_actual_create_receipt_not_mode_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root, task = Path(directory) / "root", Path(directory) / "runtime"
            (root / "receipts").mkdir(parents=True)
            path = root / "receipts" / "root-task-create.json"
            value = {"format": "sekvyr-stage7-root-task-creation-v1", "path": str(root), "uid": 0, "gid": 0, "dev": 7, "ino": 9,
                "mode": "0700", "stage": "unused-explicit-asset-stage", "runtimeProposed": str(task), "containerCreated": False, "production": False}
            path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
            def metadata(p):
                return SimpleNamespace(st_uid=0, st_gid=0, st_dev=7, st_ino=9, st_size=path.stat().st_size,
                    st_mode=(stat.S_IFREG | 0o644) if p == path else (stat.S_IFDIR | 0o700))
            with patch.object(Path, "lstat", metadata):
                self.assertEqual(cap.root_creation(root, task)[1], value)
                value["ino"] = 10
                path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "independent creation"): cap.root_creation(root, task)

    def test_creator_persists_absence_then_cid_before_caps_or_crd_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "root"
            runtime = Path(directory).resolve() / "sekvyr-stage7.deadbeef"
            backup = root / "private" / "creator"
            (root / "tools").mkdir(parents=True)
            for name in ("kind", "helm", "kubectl"): (root / "tools" / name).write_bytes(b"reviewed-public-tool")
            sources = root / "crds"
            sources.mkdir()
            for name in ("sekvyrstores.secrets.sekvyr.ru", "sekvyrsecrets.secrets.sekvyr.ru"):
                (sources / (name + ".yaml")).write_bytes(b"reviewed-public-schema")
            cid, net, imageid = "1" * 64, "3" * 64, "sha256:" + "2" * 64
            repo = cap.NODE.split("@", 1)[0].rsplit(":", 1)[0] + "@" + cap.NODE.split("@", 1)[1]
            node = {"Id": cid, "Name": "/sekvyr-stage7-deadbeef-control-plane", "Config": {"Image": cap.NODE,
                "Labels": {"io.x-k8s.kind.cluster": "sekvyr-stage7-deadbeef", "io.x-k8s.kind.role": "control-plane"}},
                "Image": imageid, "HostConfig": dict(cap.CAPS), "State": {"Running": True, "Pid": 123},
                "Mounts": [{"Type": "volume", "Name": "owned-volume"}], "NetworkSettings": {"Networks": {"kind": {"NetworkID": net}}}}
            network = {"Id": net, "Name": "kind", "Containers": {cid: {}}}
            events, made = [], {"value": False}
            def docker(*args, **kwargs):
                if args[0] == "info": return b"/var/lib/docker"
                if args[:2] == ("image", "inspect"): return canonical([{"Id": imageid, "RepoDigests": [repo]}])
                if args[:2] == ("ps", "-a"): return cid.encode() if made["value"] else b""
                if args[0] == "inspect": return canonical([node])
                if args[:2] == ("network", "inspect"): return canonical([network])
                if args[:2] == ("volume", "inspect"): return canonical([{"Name": "owned-volume"}])
                if args[0] == "update":
                    self.assertTrue((backup / "creation.json").is_file())
                    self.assertFalse((runtime / "private" / cap.MARKER).exists())
                    events.append("caps")
                    return b"owned"
                raise AssertionError("Unexpected fake Docker call")
            def run(args, **kwargs):
                if "create" in args and "cluster" in args:
                    self.assertTrue((backup / "preflight.json").is_file())
                    self.assertFalse((backup / "creation.json").exists())
                    made["value"] = True
                    (runtime / "kubeconfig").write_bytes(b"synthetic-private-config")
                    events.append("kind-create")
                    return ""
                if "chown" in args: return ""
                if "version" in args: return json.dumps({"serverVersion": {"gitVersion": "v1.37.0"}, "clientVersion": {"gitVersion": "v1.37.0"}})
                if "nodes" in args: return json.dumps({"items": [{"status": {"conditions": [{"type": "Ready", "status": "True"}]}}]})
                if "create" in args:
                    self.assertTrue((runtime / "private" / cap.MARKER).is_file())
                    events.append("CRD")
                    name = Path(args[args.index("-f") + 1]).name.removesuffix(".yaml")
                    return json.dumps({"kind": "CustomResourceDefinition", "metadata": {"name": name, "uid": "own-uid-" + name}})
                if "wait" in args: return ""
                raise AssertionError("Unexpected fake native call")
            original_read = Path.read_text
            def text(path, *args, **kwargs):
                return "MemAvailable: 16000000 kB\nMemTotal: 20000000 kB\n" if str(path).replace("\\", "/").endswith("/proc/meminfo") else original_read(path, *args, **kwargs)
            owner = SimpleNamespace(exec=lambda *args: b"\x7fELF-private-matching-kubectl", guard=Mock())
            with patch.object(creator.os, "geteuid", return_value=0, create=True), patch.object(creator.os, "getuid", return_value=0, create=True),\
                    patch.object(creator.os, "getgid", return_value=0, create=True), patch.object(creator.os, "uname", return_value=SimpleNamespace(sysname="Linux", machine="x86_64"), create=True),\
                    patch.object(creator, "paths", return_value=(root, runtime, backup)), patch.object(creator, "directory", side_effect=lambda p: {"path": str(p), "uid": 0, "dev": 1, "ino": 2}),\
                    patch.object(creator, "root_creation", return_value=(b"explicit-root-CREATE", {})), patch.object(creator, "reviewed_tool", side_effect=lambda root, path, *args: Path(path)),\
                    patch.object(creator, "runtime_capabilities"),\
                    patch.object(creator.shutil, "disk_usage", return_value=SimpleNamespace(free=100 << 30)), patch.object(Path, "read_text", text),\
                    patch.object(creator, "baseline", return_value={"containers": {}, "volumes": {}, "networks": {}, "kindNetwork": None}),\
                    patch.object(creator, "host", return_value={"bootID": "own", "daemonIDHash": "a" * 64}), patch.object(creator, "process", return_value={"pid": 123, "starttime": "own"}),\
                    patch.object(creator, "docker", side_effect=docker), patch.object(creator, "run", side_effect=run), patch.object(creator, "Capability", return_value=owner),\
                    patch.object(creator, "foreign_unchanged") as baseline_check:
                self.assertEqual(creator.create(root, runtime, root / "tools" / "kind", root / "tools" / "helm", root / "tools" / "kubectl",
                    "a" * 64, "b" * 64, "c" * 64, sources), runtime)
            self.assertEqual(events, ["kind-create", "caps", "CRD", "CRD"])
            baseline_check.assert_called_once()

    def test_baseline_normalizes_only_mount_order_and_preserves_env_args_network_and_start(self):
        value = {"Image": "sha256:" + "a" * 64, "Path": "/public-app", "Args": ["original"], "Config": {"Env": ["PUBLIC_A=first", "PUBLIC_A=second"]},
            "HostConfig": {"Memory": 123}, "Mounts": [{"Source": "one", "Destination": "/one", "RW": False}, {"Source": "two", "Destination": "/two", "RW": True}],
            "NetworkSettings": {"Networks": {"one-network": {"NetworkID": "original-id"}}}, "RestartCount": 0,
            "State": {"Running": True, "StartedAt": "2026-01-01T00:00:00Z"}}
        baseline = cap.container_snapshot(value)
        value["Mounts"].reverse()
        self.assertEqual(cap.container_snapshot(value), baseline)
        for mutate in (lambda v: v["Config"]["Env"].reverse(), lambda v: v["Args"].append("changed"),
                lambda v: v["NetworkSettings"]["Networks"]["one-network"].update(NetworkID="changed"),
                lambda v: v["State"].update(StartedAt="2026-01-01T00:01:00Z"), lambda v: v["Mounts"][0].update(RW=False)):
            altered = copy.deepcopy(value)
            mutate(altered)
            self.assertNotEqual(cap.container_snapshot(altered), baseline)


if __name__ == "__main__":
    unittest.main()
