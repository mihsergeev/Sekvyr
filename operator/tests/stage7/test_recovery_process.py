"""Local process-proof state machine tests; never sudo/fork/chroot/setns."""

import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import recovery_process as recovery


class SupervisorGuards(unittest.TestCase):
    def test_root_and_cli_need_exact_nonce_uid_parent_and_start(self):
        caller = {"pid": 10, "start": "10", "uid": 1000}
        receipt = {"nonce": "n", "pid": 100, "start": "100", "uid": 0}
        identities = {10: {"pid": 10, "start": "10", "parent": 1, "uids": [1000] * 4, "state": "S"},
            50: {"pid": 50, "start": "50", "parent": 10, "uids": [0] * 4, "state": "S"},
            100: {"pid": 100, "start": "100", "parent": 50, "uids": [0] * 4, "state": "S"}}
        with patch.object(recovery, "process_identity", side_effect=lambda pid: copy.deepcopy(identities[pid])), \
                patch.object(recovery.os, "pidfd_open", return_value=900, create=True), patch.object(recovery.os, "close"):
            self.assertEqual(recovery.pin_receipt(receipt, caller, "n")["fd"], 900)
            for field, value in (("nonce", "wrong"), ("uid", 1000), ("start", "changed")):
                with self.assertRaises(recovery.RecoveryProcessError):
                    recovery.pin_receipt(dict(receipt, **{field: value}), caller, "n")
            identities[50]["parent"] = 1
            with self.assertRaises(recovery.RecoveryProcessError):
                recovery.pin_receipt(receipt, caller, "n")
            identities[50]["parent"] = 10
            with self.assertRaises(recovery.RecoveryProcessError):
                recovery.pin_receipt(receipt, caller, "n", parent={"pid": 99, "start": "99"})

    def test_pidfd_open_race_rejects_changed_start_but_allows_running_sleep(self):
        value = {"pid": 100, "start": "100", "parent": 10, "uids": [0] * 4, "state": "R"}
        receipt = {"nonce": "n", "pid": 100, "start": "100", "uid": 0}
        with patch.object(recovery, "ancestry", return_value=True), patch.object(recovery.os, "pidfd_open", return_value=900, create=True), \
                patch.object(recovery.os, "close") as closed:
            with patch.object(recovery, "process_identity", side_effect=[value, dict(value, state="S")]):
                self.assertEqual(recovery.pin_receipt(receipt, {}, "n")["fd"], 900)
            with patch.object(recovery, "process_identity", side_effect=[value, dict(value, start="101")]):
                with self.assertRaises(recovery.RecoveryProcessError):
                    recovery.pin_receipt(receipt, {}, "n")
            closed.assert_called_once_with(900)

    def test_no_root_receipt_or_live_cli_is_not_safe_to_cleanup(self):
        root, cli = {"fd": 1}, {"fd": 2}
        with patch.object(recovery, "exited", side_effect=lambda pin: pin["fd"] == 1):
            self.assertFalse(recovery.confirmed_termination(None, None, {}, "n"))
            self.assertFalse(recovery.confirmed_termination(root, cli, {"nonce": "n", "cli_started": False}, "n"))
            self.assertFalse(recovery.confirmed_termination(root, None, None, "n"))
            self.assertFalse(recovery.confirmed_termination(root, None, {"nonce": "other", "cli_started": False}, "n"))
            self.assertTrue(recovery.confirmed_termination(root, None, {"nonce": "n", "cli_started": False}, "n"))
        with patch.object(recovery, "exited", return_value=True):
            self.assertTrue(recovery.confirmed_termination(root, cli, None, "n"))

    def test_atomic_gate_is_exclusive_and_profile_is_not_plan_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate"
            recovery._gate(path, "nonce")
            self.assertEqual(path.read_bytes(), b"nonce")
            with self.assertRaises(recovery.RecoveryProcessError):
                recovery._gate(path, "other")
        for profile in ("kind", "host"):
            compile(recovery.driver_source(profile), "fixed-root-profile", "exec")
        with self.assertRaises(recovery.RecoveryProcessError):
            recovery.driver_source("incoming-untrusted-source")

    def test_complete_protocol_pins_two_processes_without_credentials_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "launch.json"
            raw = b'{"sandbox":"synthetic"}'
            plan.write_bytes(raw)
            nonce = "f" * 32
            identities = {10: {"pid": 10, "start": "10", "parent": 1, "uids": [1000] * 4, "state": "S"},
                50: {"pid": 50, "start": "50", "parent": 10, "uids": [1000] * 4, "state": "S"},
                100: {"pid": 100, "start": "100", "parent": 50, "uids": [0] * 4, "state": "S"},
                101: {"pid": 101, "start": "101", "parent": 100, "uids": [0] * 4, "state": "S"}}
            command = []
            class Child:
                pid, returncode = 50, 0
                def __init__(self, argv, **kwargs): command.extend(argv)
                def communicate(self, timeout): return b"CheckpointRecoveryComplete\n", b""
                def poll(self): return None
            def receipt(path):
                if path.name == "root-ready.json": return {"nonce": nonce, "pid": 100, "start": "100", "uid": 0}
                if path.name == "cli-ready.json" and (root / "root-go").exists():
                    return {"nonce": nonce, "pid": 101, "start": "101", "uid": 0}
                if path.name == "root-done.json": return {"nonce": nonce, "cli_started": True, "cli_pid": 101,
                    "cli_start": "101", "cli_reaped": True, "complete": True}
            with patch.object(recovery.uuid, "uuid4", return_value=SimpleNamespace(hex=nonce)), \
                    patch.object(recovery.os, "getpid", return_value=10), patch.object(recovery.os, "getuid", return_value=1000, create=True), \
                    patch.object(recovery.os, "getgid", return_value=1000, create=True), \
                    patch.object(recovery, "process_identity", side_effect=lambda pid: identities[pid]), \
                    patch.object(recovery.os, "pidfd_open", side_effect=lambda pid: pid + 1000, create=True), \
                    patch.object(recovery.os, "close") as close, patch.object(recovery, "_receipt", side_effect=receipt), \
                    patch.object(recovery, "exited", side_effect=lambda pin: (root / "cli-go").exists()), \
                    patch.object(recovery.subprocess, "Popen", Child):
                result = recovery.run_recovery(plan, raw, "host")
            self.assertTrue(result["terminationConfirmed"])
            self.assertEqual({call.args[0] for call in close.call_args_list}, {1100, 1101})
            self.assertIn("--allow-trial-canonical-ledger", command[command.index("-c") + 1])
            self.assertNotIn("SYNTHETIC_PRIVATE_CREDENTIAL", " ".join(command))
            self.assertNotIn("setns", recovery.driver_source("host"))

    def test_pidfd_signal_guard_does_not_signal_reused_pid(self):
        # Execute only the tiny signal guard with fake imported OS/proc modules.
        import types
        import sys
        for actual, expected_calls in (("100", 1), ("101", 0)):
            fields = ["S", "10"] + ["0"] * 17 + [actual]
            raw = "99 (synthetic) " + " ".join(fields)
            calls = []
            fake_os = types.SimpleNamespace(pidfd_open=lambda pid: 900, close=lambda fd: None)
            fake_path = types.SimpleNamespace(Path=lambda path: types.SimpleNamespace(read_text=lambda: raw))
            fake_signal = types.SimpleNamespace(SIGKILL=9, pidfd_send_signal=lambda fd, sig: calls.append((fd, sig)))
            fake_sys = types.SimpleNamespace(argv=["guard", "99", "100"], exit=lambda code=0: (_ for _ in ()).throw(SystemExit(code)))
            with patch.dict(sys.modules, os=fake_os, pathlib=fake_path, signal=fake_signal, sys=fake_sys):
                try: exec(recovery.KILL_PINNED, {})
                except SystemExit: pass
            self.assertEqual(len(calls), expected_calls)


if __name__ == "__main__":
    unittest.main()
