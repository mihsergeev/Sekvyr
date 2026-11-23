"""The updater must stop before pulling images when the requested tag is overridden."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


UPDATE = Path(__file__).resolve().parents[1] / "update.sh"


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "POSIX shell required")
class UpdateImagePinsTest(unittest.TestCase):
    def run_update(self, backend, frontend, *, config_status=0, pull_status=42):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ops").mkdir()
            shutil.copyfile(UPDATE.with_name("check_compose_networks.py"), root / "ops/check_compose_networks.py")
            (root / ".env").write_text("COMPOSE_FILE=compose.yml:compose.ghcr.yml\nSEKVYR_IMAGE_TAG=1.1.0\n")
            (root / "compose.yml").touch()
            backup = root / "ops/backup.sh"
            backup.write_text("#!/bin/sh\nexit 0\n")
            backup.chmod(0o755)
            git = root / "git"
            git.write_text('''#!/bin/sh
case "$1" in
    rev-parse) case "$*" in *HEAD*) echo before;; *) echo target;; esac;;
    diff|fetch|checkout) exit 0;;
    describe|merge-base|show-ref) exit 1;;
    *) exit 99;;
esac
''')
            docker = root / "docker"
            docker.write_text('''#!/bin/sh
case "$*" in
    'compose ps') exit 0;;
    'compose config --format json') printf '%s\n' '{"services":{}}';;
    'compose config backend frontend') cat compose-rendered.yml; exit "$CONFIG_STATUS";;
    'compose pull backend frontend') touch pull-was-called; exit "$PULL_STATUS";;
    'compose up -d --pull missing') test "$SEKVYR_IMAGE_TAG" = 1.2.0;;
    'compose exec -T backend python -c '*) exit 0;;
    *) exit 99;;
esac
''')
            for program in (git, docker):
                program.chmod(0o755)
            (root / "compose-rendered.yml").write_text(
                f"services:\n  backend:\n    image: {backend}\n"
                f"  db:\n    image: db@sha256:{'a' * 64}\n"
                f"  frontend:\n    image: {frontend}\n"
            )
            result = subprocess.run(
                ["sh", str(UPDATE), "v1.2.0"], cwd=root, text=True,
                capture_output=True, timeout=10, env={
                    **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                    "SEKVYR_APP": str(root), "SEKVYR_LANG": "en", "CONFIG_STATUS": str(config_status),
                    "PULL_STATUS": str(pull_status), "SEKVYR_IMAGE_TAG": "1.1.0",
                },
            )
            return result, (root / "pull-was-called").exists()

    def test_fixed_digest_and_old_tag_both_stop_the_upgrade(self):
        for frontend, message in (
            (f"frontend@sha256:{'b' * 64}", "pinned by digest"),
            ("frontend:1.1.0", "do not use the requested tag"),
        ):
            with self.subTest(frontend=frontend):
                result, pulled = self.run_update("backend:1.2.0", frontend)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(pulled)

    def test_both_matching_tags_proceed_even_with_a_digest_pinned_database(self):
        result, pulled = self.run_update("backend:1.2.0", "frontend:1.2.0")
        self.assertTrue(pulled)
        self.assertIn("could not be pulled", result.stderr)

    def test_failed_render_is_not_treated_as_a_valid_config(self):
        result, pulled = self.run_update("backend:1.2.0", "frontend:1.2.0", config_status=7)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("both panel images must be present", result.stderr)
        self.assertFalse(pulled)

    def test_launch_uses_verified_tag_even_with_stale_exported_tag(self):
        result, pulled = self.run_update("backend:1.2.0", "frontend:1.2.0", pull_status=0)
        self.assertTrue(pulled)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("git"), "Git required")
    def test_new_checkout_cannot_replace_the_preflighted_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    ["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL,
                ).strip()

            git("init", "-b", "installed")
            git("config", "user.email", "test@example.com")
            git("config", "user.name", "Fixture")
            compose = root / "compose.yml"
            compose.write_text(
                "services:\n  backend:\n    image: backend:IMAGE_TAG\n"
                "  frontend:\n    image: frontend:IMAGE_TAG\n"
            )
            env_file = root / ".env"
            initial_env = "COMPOSE_FILE=compose.yml:compose.ghcr.yml\nSEKVYR_IMAGE_TAG=1.1.0\n"
            env_file.write_text(initial_env)
            (root / "ops").mkdir()
            backup = root / "ops/backup.sh"
            shutil.copyfile(UPDATE.with_name("check_compose_networks.py"), root / "ops/check_compose_networks.py")
            backup.write_text("#!/bin/sh\ntouch backup-was-called\n")
            backup.chmod(0o755)
            git("add", "compose.yml", "ops/backup.sh", "ops/check_compose_networks.py")
            git("commit", "-m", "installed version")
            before = git("rev-parse", "HEAD")
            git("tag", "v1.1.0")
            git("switch", "-c", "release")
            compose.write_text(compose.read_text().replace("frontend:IMAGE_TAG", "frontend:1.1.0"))
            git("commit", "-am", "pin an old frontend image")
            git("tag", "v1.2.0")
            git("switch", "installed")
            docker = root / "docker"
            docker.write_text('''#!/bin/sh
case "$*" in
    'compose ps') exit 0;;
    'compose config --format json') printf '%s\n' '{"services":{}}';;
    'compose config backend frontend') sed "s/IMAGE_TAG/$SEKVYR_IMAGE_TAG/g" compose.yml;;
    'compose pull backend frontend') touch pull-was-called;;
    'compose up -d --pull missing') touch up-was-called; exit 1;;
    *) exit 99;;
esac
''')
            docker.chmod(0o755)
            for colliding_branch in (False, True):
                with self.subTest(colliding_branch=colliding_branch):
                    if colliding_branch:
                        git("branch", "v1.2.0")
                    for marker in ("pull-was-called", "backup-was-called", "up-was-called"):
                        (root / marker).unlink(missing_ok=True)
                    result = subprocess.run(
                        ["sh", str(UPDATE), "v1.2.0"], cwd=root, text=True,
                        capture_output=True, timeout=10, env={
                            **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                            "SEKVYR_APP": str(root), "SEKVYR_LANG": "en",
                        },
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("changes the Compose image references", result.stderr)
                    self.assertTrue((root / "pull-was-called").exists())
                    self.assertTrue((root / "backup-was-called").exists())
                    self.assertFalse((root / "up-was-called").exists())
                    self.assertEqual(git("rev-parse", "HEAD"), before)
                    self.assertEqual(git("branch", "--show-current"), "installed")
                    self.assertEqual(env_file.read_text(), initial_env)
