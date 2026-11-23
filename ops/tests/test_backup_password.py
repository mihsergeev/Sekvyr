"""Check backup initialization through the same script used by cron."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


BACKUP = Path(__file__).resolve().parents[1] / "backup.sh"
RESTORE = BACKUP.with_name("restore.sh")
FIXTURE_PASSWORD = "synthetic-backup-test-material"


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "POSIX shell required")
class BackupPasswordTest(unittest.TestCase):
    def run_backup(self, root, openssl):
        (root / "compose.yml").touch()
        (root / ".env").write_text("SEKVYR_LANG=en\n")
        for name, script in {
            "openssl": openssl,
            "chown": "exit 0",
            "docker": '''case "$*" in
    'compose ps') exit 0;;
    'compose exec -T db pg_dump '*) printf 'fixture dump';;
    'compose run --rm --no-deps -T --entrypoint python backend -m app.cli seal '*)
        cat >/dev/null
        test -s secret/backup.pass || exit 9
        head -c 8192 /dev/zero;;
    *) exit 99;;
esac''',
        }.items():
            executable = root / name
            executable.write_text(f"#!/bin/sh\n{script}\n")
            executable.chmod(0o755)
        return subprocess.run(
            ["sh", str(BACKUP)], cwd=root, capture_output=True, text=True, timeout=10,
            env={**os.environ, "SEKVYR_APP": str(root), "SEKVYR_LANG": "en",
                 "SEKVYR_BACKUP_DIR": str(root / "backups"), "SEKVYR_BACKUP_OFFSITE": "",
                 "PATH": f"{root}:{os.environ['PATH']}"},
        )

    def test_first_backup_keeps_generated_password_out_of_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_backup(root, f"echo {FIXTURE_PASSWORD}")
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertNotIn(FIXTURE_PASSWORD, output)
            path = root / "secret/backup.pass"
            self.assertIn(str(path), output)
            self.assertEqual(path.read_text(), FIXTURE_PASSWORD)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(list((root / "backups").glob("*.sql.sealed"))), 1)

    def test_failed_generator_leaves_no_password_or_completed_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_backup(root, "exit 1")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("could not generate the backup password", result.stderr)
            self.assertFalse((root / "secret/backup.pass").exists())
            self.assertFalse(list((root / "backups").glob("*.sql.sealed")))

    def test_status_write_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / "host-canary"
            canary.write_text("keep\n")
            data = root / "data"
            data.mkdir()
            status = data / "backup.json"
            status.symlink_to(canary)
            result = self.run_backup(root, f"echo {FIXTURE_PASSWORD}")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(canary.read_text(), "keep\n")
            self.assertFalse(status.is_symlink())

    def test_rejects_a_symlink_as_password_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / "host-canary"
            canary.write_text("keep\n")
            (root / "secret").mkdir()
            (root / "secret/backup.pass").symlink_to(canary)
            result = self.run_backup(root, f"echo {FIXTURE_PASSWORD}")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("backup password file must be a regular file", result.stderr)
            self.assertEqual(canary.read_text(), "keep\n")
            self.assertFalse(list((root / "backups").glob("*.sql.sealed")))

    def test_restore_never_sends_a_symlink_target_to_the_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compose.yml").touch()
            (root / ".env").touch()
            canary = root / "host-canary"
            canary.write_text("synthetic host-only content\n")
            (root / "secret").mkdir()
            (root / "secret/backup.pass").symlink_to(canary)
            sealed = root / "fixture.sql.sealed"
            sealed.write_text("SEKVYR-SEALED\n")
            docker = root / "docker"
            docker.write_text('''#!/bin/sh
[ "$*" != 'compose ps' ] || exit 0
IFS= read -r password
printf '%s\n' "$password" >> forwarded
cat >/dev/null
exit 1
''')
            docker.chmod(0o755)
            result = subprocess.run(
                ["sh", str(RESTORE), str(sealed)], cwd=root, input="sekvyr\nmanual\n",
                capture_output=True, text=True, timeout=10,
                env={**os.environ, "SEKVYR_APP": str(root), "SEKVYR_LANG": "en",
                     "PATH": f"{root}:{os.environ['PATH']}"},
            )
            self.assertNotEqual(result.returncode, 0)
            forwarded = root / "forwarded"
            self.assertFalse(forwarded.exists(), "Restore forwarded a host-only file to Docker")
            self.assertIn("backup password file must be a regular file", result.stderr)
