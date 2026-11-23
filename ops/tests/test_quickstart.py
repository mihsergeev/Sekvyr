"""Quickstart must preserve existing files and take a backup before an upgrade."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


OPS = Path(__file__).resolve().parents[1]
INSTALLERS = ("quickstart.sh", "quickstart-ru.sh")


def program(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "POSIX shell required")
class QuickstartSafetyTest(unittest.TestCase):
    def run_quickstart(self, installer, *, database="initialized", query_status=0, backup_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            panel = root / "panel"
            panel.mkdir()
            (panel / ".git").mkdir()
            env_file = panel / ".env"
            original = "SEKVYR_DOMAIN=panel.example\n"
            env_file.write_text(original)
            (panel / "ops").mkdir()

            program(root / "id", "echo 0\n")
            program(root / "ss", "exit 0\n")
            program(root / "git", 'echo git >> "$TRACE"; exit 42\n')
            program(root / "docker", '''
case "$*" in
    'network inspect caddy --format '* ) echo true;;
    'ps --format '* ) echo caddy-docker-proxy;;
    *pg_isready* ) exit 0;;
    *psql* ) printf '%s\\n' "$DATABASE"; exit "$QUERY_STATUS";;
esac
''')
            if backup_status is not None:
                program(panel / "ops/backup.sh", 'echo backup >> "$TRACE"; exit "$BACKUP_STATUS"\n')
            trace = root / "trace"
            trace.touch()
            result = subprocess.run(
                ["sh", str(OPS / installer), "--dir", str(panel), "--domain", "panel.example", "--no-cron"],
                text=True, capture_output=True, timeout=10, env={
                    **os.environ, "PATH": f"{root}:{os.environ['PATH']}", "TRACE": str(trace),
                    "DATABASE": database, "QUERY_STATUS": str(query_status), "BACKUP_STATUS": str(backup_status),
                },
            )
            self.assertEqual(env_file.read_text(), original)
            self.assertNotEqual(result.returncode, 0)
            return trace.read_text().splitlines()

    def test_database_probe_failure_blocks_both_installers(self):
        for installer in INSTALLERS:
            for database, status in (("", 1), ("empty", 1), ("unexpected", 0)):
                with self.subTest(installer=installer, database=database, status=status):
                    self.assertEqual(self.run_quickstart(installer, database=database, query_status=status), [])

    def test_initialized_database_requires_backup_before_git(self):
        for installer in INSTALLERS:
            with self.subTest(installer=installer):
                self.assertEqual(self.run_quickstart(installer, backup_status=None), [])
                self.assertEqual(self.run_quickstart(installer, backup_status=1), ["backup"])
                self.assertEqual(self.run_quickstart(installer), ["backup", "git"])
                self.assertEqual(self.run_quickstart(installer, database="empty"), ["git"])

    def test_clone_preserves_unrelated_files(self):
        for installer in INSTALLERS:
            for scenario in ("failed", "conflict", "success"):
                with self.subTest(installer=installer, scenario=scenario), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    panel = root / "panel"
                    sibling = root / "panel.tmp"
                    sibling.mkdir()
                    (sibling / "keep").write_text("sibling")
                    if scenario == "success":
                        panel.mkdir()
                    program(root / "id", "echo 0\n")
                    program(root / "ss", "exit 0\n")
                    program(root / "openssl", "echo synthetic-fixture-value\n")
                    program(root / "docker", '''
case "$*" in
    'network inspect caddy --format '* ) echo true;;
    'ps --format '* ) echo caddy-docker-proxy;;
    *'config --format json') echo '{"services":{}}';;
esac
''')
                    program(root / "git", '''
case "$1" in
    tag) echo v1.0.0; exit 0;;
    show) cat "$NETWORK_CHECK"; exit 0;;
    checkout|pull) exit 0;;
    clone) ;;
    *) exit 42;;
esac
mkdir -p "$4/.git"
case "$SCENARIO" in
    failed) exit 42;;
    conflict) mkdir "$PANEL"; printf concurrent > "$PANEL/keep";;
    success) cp "$ENV_EXAMPLE" "$4/.env.example";;
esac
''')
                    result = subprocess.run(
                        ["sh", str(OPS / installer), "--dir", str(panel), "--domain", "panel.example", "--no-cron"],
                        capture_output=True, timeout=10, env={
                            **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                            "PANEL": str(panel), "SCENARIO": scenario, "ENV_EXAMPLE": str(OPS.parent / ".env.example"),
                            "NETWORK_CHECK": str(OPS / "check_compose_networks.py"),
                        },
                    )
                    self.assertEqual(result.returncode == 0, scenario == "success")
                    self.assertEqual((sibling / "keep").read_text(), "sibling")
                    self.assertEqual(list(root.glob(".sekvyr-clone.*")), [])
                    if scenario == "conflict":
                        self.assertEqual((panel / "keep").read_text(), "concurrent")
                    elif scenario == "failed":
                        self.assertFalse(panel.exists())
                    else:
                        self.assertTrue((panel / ".git").is_dir())
                        self.assertIn("SEKVYR_DOMAIN=panel.example\n", (panel / ".env").read_text())
