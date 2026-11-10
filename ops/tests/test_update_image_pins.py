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
    def run_update(self, backend, frontend, *, config_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("COMPOSE_FILE=compose.yml:compose.ghcr.yml\nSEKVYR_IMAGE_TAG=1.1.0\n")
            (root / "compose.yml").touch()
            git = root / "git"
            git.write_text('''#!/bin/sh
case "$1" in
    rev-parse) case "$*" in *HEAD*) echo before;; *) echo target;; esac;;
    diff|fetch) exit 0;;
    describe|merge-base|show-ref) exit 1;;
    *) exit 99;;
esac
''')
            docker = root / "docker"
            docker.write_text('''#!/bin/sh
case "$*" in
    'compose ps') exit 0;;
    'compose config backend frontend') cat compose-rendered.yml; exit "$CONFIG_STATUS";;
    'compose pull backend frontend') touch pull-was-called; exit 42;;
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
