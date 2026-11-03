"""Stage 8 recovery guards. No fork, sudo, Docker, chroot or setns."""

import ast
import hashlib
import json
import os
import re
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fixture import canonical
from stage8 import profiles, recovery
import remote_kind_recovery as legacy
import recovery_process as supervisor
import kind_recovery
from test_remote_kind import fixture_file_uid
from stage8.test_profiles import SYNTHETIC

class RecoveryGuards(unittest.TestCase):
    def setUp(self):
        pin = patch.object(profiles, "REVIEWED_ARTIFACTS", SYNTHETIC)
        pin.start()
        self.addCleanup(pin.stop)

    def test_driver_keeps_exact_net_fd_root_supervisor_and_fixed_closed_profile(self):
        old_globals = dict(supervisor.run_recovery.__globals__)
        for profile in ("kind-1.37.0", "kind-1.34.11"):
            code = recovery.driver_source(profile)
            ast.parse(code)
            self.assertIn(kind_recovery.NET_JOIN, code)
            self.assertTrue(code.startswith(supervisor.ROOT_PREFIX + "\n"))
            self.assertTrue(code.endswith("\n" + supervisor.ROOT_MAIN))
            self.assertIn(profiles.node_profile(profile).node, code)
            self.assertIn(SYNTHETIC["recovery_sha256"], code)
            self.assertIn("pidfd", code)
        self.assertEqual(supervisor.run_recovery.__globals__, old_globals)
        with self.assertRaises(RuntimeError): recovery.driver_source("incoming-plan-module")

    def test_changed_legacy_template_is_rejected_not_silently_rewritten(self):
        with patch.object(legacy, "ROOT_SETUP", legacy.ROOT_SETUP + "\n# drift"), self.assertRaises(RuntimeError):
            recovery.root_setup_source("kind-1.37.0")
        with patch.object(legacy, "NET_JOIN", legacy.NET_JOIN + "\n# drift"), self.assertRaises(RuntimeError):
            recovery.root_setup_source("kind-1.37.0")

    def stage8_guard(self, profile):
        source = ast.parse(recovery.root_setup_source(profile))
        setup = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == "root_setup")
        wrapper = [n for n in setup.body if isinstance(n, ast.FunctionDef) and n.name == "guard"][-1]
        static = ast.literal_eval(next(n.value for n in source.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "EXPECTED_STAGE8" for t in n.targets)))
        root, task = Path("/opt/sekvyr-trial/sekvyr-stage7-20261103-deadbeef"), Path("/var/tmp/sekvyr-stage7.deadbeef")
        path = root / "receipts" / "stage8-profile.json"
        marker, preflight = task / "private" / "remote-kind-capability.json", root / "private" / "creator" / "preflight.json"
        record = dict(static, rootTask=str(root), runtimeTask=str(task), rootCreationReceiptSHA256="e" * 64)
        mapping = {str(marker): canonical({"rootTask":str(root),"runtimeTask":str(task)}),
            str(preflight):canonical({"rootCreationReceiptSHA256":"e"*64,
                "stage8ProfileSHA256":hashlib.sha256(canonical(record)).hexdigest()}), str(path):canonical(record)}
        plan = {"capabilityPath":str(marker),"preflightPath":str(preflight),"stage8ProfilePath":str(path),
            "stage8ProfileSHA256":hashlib.sha256(mapping[str(path)]).hexdigest()}
        original = Mock()
        def need(value):
            if not value: raise RuntimeError("Denied")
        scope = {"private":lambda p:mapping[str(p)],"p":plan,"pathlib":__import__("pathlib"),
            "hashlib":hashlib,"json":json,"re":re,"EXPECTED_STAGE8":static,"need":need,"original_guard":original}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[])), "reviewed-stage8-only-guard", "exec"),scope)
        return scope["guard"], original, mapping, plan, path, record

    def test_profile_guard_runs_before_old_docker_guard_and_rejects_other_minor_or_build(self):
        for profile in ("kind-1.37.0", "kind-1.34.11"):
            check, original, mapping, plan, path, record = self.stage8_guard(profile)
            check();original.assert_called_once()
            original.reset_mock()
            for key, value in (("profile","foreign"),("artifacts",dict(SYNTHETIC,recovery_sha256="f"*64))):
                bad = dict(record, **{key:value}); mapping[str(path)]=canonical(bad)
                plan["stage8ProfileSHA256"]=hashlib.sha256(mapping[str(path)]).hexdigest()
                pre = json.loads(mapping[plan["preflightPath"]])
                pre["stage8ProfileSHA256"] = plan["stage8ProfileSHA256"]
                mapping[plan["preflightPath"]] = canonical(pre)
                with self.assertRaises(RuntimeError):check()
                original.assert_not_called()

    def test_profile_receipt_byte_tamper_or_wrong_path_denies_before_old_guard(self):
        check, original, mapping, plan, path, _ = self.stage8_guard("kind-1.37.0")
        mapping[str(path)]+=b" "
        with self.assertRaises(RuntimeError):check()
        original.assert_not_called()

    def test_plan_paths_are_bounded_before_first_private_file_read(self):
        for field, value in (("capabilityPath", "/root/other-private.json"),
                ("preflightPath", "/root/other-private.json")):
            check, original, mapping, plan, _, _ = self.stage8_guard("kind-1.37.0")
            plan[field] = value
            with self.assertRaises(RuntimeError): check()
            original.assert_not_called()
            self.assertNotIn(value, mapping)

    def test_root_guard_rejects_missing_preflight_pin_and_noncanonical_profile(self):
        check, original, mapping, plan, path, _ = self.stage8_guard("kind-1.37.0")
        pre = json.loads(mapping[plan["preflightPath"]]); del pre["stage8ProfileSHA256"]
        mapping[plan["preflightPath"]] = canonical(pre)
        with self.assertRaises(RuntimeError): check()
        original.assert_not_called()
        raw = mapping[str(path)] + b" "
        mapping[str(path)] = raw; plan["stage8ProfileSHA256"] = hashlib.sha256(raw).hexdigest()
        pre["stage8ProfileSHA256"] = plan["stage8ProfileSHA256"]
        mapping[plan["preflightPath"]] = canonical(pre)
        with self.assertRaises(RuntimeError): check()
        original.assert_not_called()
        plan["stage8ProfilePath"]="another-root-receipt"
        with self.assertRaises(RuntimeError):check()
        original.assert_not_called()

    def test_exact_new_cli_hash_repo_and_static_loader_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            task=Path(directory);(task/"tools").mkdir()
            executable=task/"tools"/"sekvyr-checkpoint-recovery"
            raw=bytearray(120);raw[:6]=b"\x7fELF\x02\x01"
            struct.pack_into("<H",raw,18,62);struct.pack_into("<Q",raw,32,64)
            struct.pack_into("<H",raw,54,56);struct.pack_into("<H",raw,56,1)
            executable.write_bytes(raw)
            pins=dict(SYNTHETIC,recovery_sha256=hashlib.sha256(raw).hexdigest())
            proof={"image":pins["operator_image"],"sha256":pins["recovery_sha256"]}
            panel=SimpleNamespace(task=task,recovery_executable=executable)
            with patch.object(profiles,"REVIEWED_ARTIFACTS",pins), fixture_file_uid(executable,0), \
                    patch.object(legacy,"read",side_effect=lambda p:(b"",proof)):
                self.assertEqual(recovery.verified_cli(panel,profile="kind-1.34.11"),raw)
                proof["image"]="another.invalid/alias@"+pins["operator_image"].split("@")[1]
                with self.assertRaises(RuntimeError):recovery.verified_cli(panel,profile="kind-1.34.11")
                proof["image"]=pins["operator_image"]
                executable.write_bytes(raw+b"tamper")
                with self.assertRaises(RuntimeError):recovery.verified_cli(panel,profile="kind-1.34.11")
            struct.pack_into("<I",raw,64,3);executable.write_bytes(raw)
            pins["recovery_sha256"]=hashlib.sha256(raw).hexdigest();proof["sha256"]=pins["recovery_sha256"]
            with patch.object(profiles,"REVIEWED_ARTIFACTS",pins), fixture_file_uid(executable,0), patch.object(legacy,"read",return_value=(b"",proof)):
                with self.assertRaisesRegex(RuntimeError,"loader"):recovery.verified_cli(panel,profile="kind-1.34.11")
            with patch.object(profiles,"REVIEWED_ARTIFACTS",pins), fixture_file_uid(executable,1001), patch.object(legacy,"read",return_value=(b"",proof)):
                with self.assertRaises(RuntimeError):recovery.verified_cli(panel,profile="kind-1.34.11")

    def test_unset_pins_cannot_create_callback_or_read_private_binary(self):
        with patch.object(profiles,"REVIEWED_ARTIFACTS",dict.fromkeys(SYNTHETIC)), patch.object(legacy,"read") as read:
            with self.assertRaises(RuntimeError):recovery.bind(None,"kind-1.37.0")
            with self.assertRaises(RuntimeError):recovery.recover(None,None,None,None,None,profile="kind-1.37.0")
        read.assert_not_called()

    def test_private_shared_run_retains_termination_fact_and_never_launches_real_process(self):
        for launched in (False,True):
            with tempfile.TemporaryDirectory() as temporary:
                task=Path(temporary);(task/"private").mkdir()
                config=task/"kubeconfig";config.write_bytes(b"synthetic-config")
                owner=SimpleNamespace(task=task,exec=Mock(return_value=b"own-admin"),guard=Mock(),
                    root_plan=lambda:{},creator={"process":{"pid":123,"starttime":"owned"}})
                panel=SimpleNamespace(task=task,cluster=SimpleNamespace(namespaces={"trial-apps"},config=config))
                child=SimpleNamespace(pid=50,communicate=Mock(return_value=(b"",b"")))
                identities=[{"start":"known-caller"},RuntimeError("SYNTHETIC_PRIVATE_CANARY")]
                with patch.object(recovery,"Capability",return_value=owner), patch.object(recovery,"verified_cli",return_value=b"static"), \
                        patch.object(legacy,"recovery_kubeconfig",return_value=b"private"), patch.object(legacy,"database_resolver",return_value=b"nameserver 192.0.2.53\n"), \
                        patch.object(legacy,"cleanup_sandbox") as cleanup, patch.object(supervisor.os,"getuid",return_value=1000,create=True), \
                        patch.object(supervisor.os,"getgid",return_value=1000,create=True), \
                        patch.object(supervisor,"process_identity",side_effect=identities), \
                        patch.object(supervisor.subprocess,"Popen",return_value=child,side_effect=None if launched else OSError("SYNTHETIC_PRIVATE_CANARY")):
                    with self.assertRaises(RuntimeError) as failure:
                        recovery.recover(panel,{"body":{"allow_rollout":False}},b"ciphertext",b"wrap",
                            {"namespace":"trial-apps","ha":{"trial":True}},profile="kind-1.37.0")
                self.assertIs(failure.exception.termination_confirmed,not launched)
                self.assertIs(cleanup.call_args.args[-1],not launched)
                self.assertNotIn("SYNTHETIC_PRIVATE_CANARY",str(failure.exception))
