"""A static panel IP must survive a dynamic peer starting first."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


OPS = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compose_networks", OPS / "check_compose_networks.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def config(backend=None, frontend=None, *, pools=(), external=False):
    return {"services": {
        "backend": {"networks": {"internal": backend}},
        "frontend": {"networks": {"internal": frontend}},
        "edge": {"network_mode": "host", "networks": None},
    }, "networks": {"internal": {"name": "fixture", "external": external, "ipam": {"config": list(pools)}}}}


class ComposeNetworkTest(unittest.TestCase):
    def check(self, value, existing=()):
        CHECK.validate(value, lambda _: list(existing))

    def test_default_dynamic_and_distinct_static_addresses_are_safe(self):
        self.check(config())
        self.check(config({"ipv4_address": "192.0.2.10"}, {"ipv4_address": "192.0.2.11"}))

    def test_original_boot_collision_is_rejected_with_an_existing_network(self):
        with self.assertRaises(ValueError):
            self.check(config({"ipv4_address": "192.0.2.10"}), [{"Subnet": "192.0.2.0/24", "IPRange": ""}])

    def test_static_address_must_be_outside_every_dynamic_pool(self):
        value = config({"ipv4_address": "192.0.2.10"}, pools=[{"subnet": "192.0.2.0/24", "ip_range": "192.0.2.128/25"}])
        self.check(value)
        for pool in ({"subnet": "192.0.2.0/24"}, {"subnet": "192.0.2.0/24", "ip_range": "192.0.2.0/25"},
                     {"subnet": "198.51.100.0/24", "ip_range": "198.51.100.128/25"}):
            with self.subTest(pool=pool), self.assertRaises(ValueError):
                changed = copy.deepcopy(value)
                changed["networks"]["internal"]["ipam"]["config"].append(pool)
                # A separate nonoverlapping subnet does not expose the static IP.
                if pool["subnet"] == "198.51.100.0/24":
                    changed["networks"]["internal"]["ipam"]["config"] = [pool]
                self.check(changed)

    def test_ipv6_and_external_networks_use_the_same_allocation_rule(self):
        value = config({"ipv6_address": "2001:db8::10"}, external=True)
        self.check(value, [{"Subnet": "2001:db8::/64", "IPRange": "2001:db8::8000/113"}])
        with self.assertRaises(ValueError):
            self.check(value, [{"Subnet": "2001:db8::/64"}])
        with self.assertRaises(ValueError):
            self.check(config({"ipv4_address": "192.0.2.10"}, {"ipv4_address": "192.0.2.11"}, external=True))

    def test_logical_aliases_cannot_hide_a_duplicate_address(self):
        value = config({"ipv4_address": "192.0.2.10"})
        value["networks"]["alias"] = {"name": "fixture"}
        value["services"]["frontend"]["networks"] = {"alias": {"ipv4_address": "192.0.2.10"}}
        with self.assertRaises(ValueError):
            self.check(value)

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "POSIX shell required")
    def test_update_refuses_unsafe_overlay_before_fetch_backup_or_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ops").mkdir()
            shutil.copyfile(OPS / "check_compose_networks.py", root / "ops/check_compose_networks.py")
            (root / "compose.yml").touch()
            (root / ".env").write_text("COMPOSE_FILE=compose.yml:compose.ghcr.yml\n")
            (root / "render.json").write_text(json.dumps(config({"ipv4_address": "192.0.2.10"})))
            for name, body in {
                "git": 'touch git-was-called; exit 99',
                "docker": 'case "$*" in "compose ps") exit 0;; "compose config --format json") cat render.json;; *) exit 99;; esac',
            }.items():
                program = root / name
                program.write_text("#!/bin/sh\n" + body + "\n")
                program.chmod(0o755)
            result = subprocess.run(["sh", str(OPS / "update.sh"), "v1.2.0"], cwd=root, capture_output=True,
                                    timeout=10, env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                                                     "SEKVYR_APP": str(root), "SEKVYR_LANG": "en"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"address safety could not be verified", result.stderr)
            self.assertFalse((root / "git-was-called").exists())

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "POSIX shell required")
    def test_cli_hides_credentials_on_render_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            docker = Path(directory) / "docker"
            docker.write_text("#!/bin/sh\necho synthetic-credential >&2\nexit 1\n")
            docker.chmod(0o755)
            result = subprocess.run(["python3", str(OPS / "check_compose_networks.py")], capture_output=True,
                                    env={**os.environ, "PATH": f"{directory}:{os.environ['PATH']}"})
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"synthetic-credential", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "POSIX shell required")
    def test_both_quickstarts_keep_the_check_when_installing_an_old_tag(self):
        for installer in ("quickstart.sh", "quickstart-ru.sh"):
            with self.subTest(installer=installer), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                panel = root / "panel"
                render = root / "render.json"
                render.write_text(json.dumps(config({"ipv4_address": "192.0.2.10"})))
                programs = {
                    "id": "echo 0",
                    "ss": "exit 0",
                    "openssl": "echo synthetic-fixture-value",
                    "git": '''case "$1" in
    clone) mkdir -p "$4/.git"; cp "$ENV_EXAMPLE" "$4/.env.example";;
    show) cat "$CHECKER";;
    tag) echo v1.0.3;;
    checkout) rm -f ops/check_compose_networks.py;;
    *) exit 99;;
esac''',
                    "docker": '''case "$*" in
    'network inspect caddy --format '*) echo true;;
    'network inspect caddy') exit 0;;
    'ps --format '*) echo caddy-docker-proxy;;
    'compose version') exit 0;;
    'compose config --format json') cat "$RENDER";;
    *' up '*) touch "$START_MARKER"; exit 99;;
    *) exit 99;;
esac''',
                }
                for name, body in programs.items():
                    program = root / name
                    program.write_text("#!/bin/sh\n" + body + "\n")
                    program.chmod(0o755)
                marker = root / "started"
                result = subprocess.run(["sh", str(OPS / installer), "--dir", str(panel),
                                         "--domain", "panel.example", "--no-cron"],
                                        capture_output=True, timeout=10, env={
                                            **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                                            "ENV_EXAMPLE": str(OPS.parent / ".env.example"),
                                            "CHECKER": str(OPS / "check_compose_networks.py"),
                                            "RENDER": str(render), "START_MARKER": str(marker),
                                        })
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"ip_range", result.stderr)
                self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix" and shutil.which("git"), "POSIX Git required")
    def test_upgrade_restores_checkout_if_the_new_release_changes_network_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()

            git("init", "-b", "installed")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "test@example.com")
            (root / "ops").mkdir()
            shutil.copyfile(OPS / "check_compose_networks.py", root / "ops/check_compose_networks.py")
            backup = root / "ops/backup.sh"
            backup.write_text("#!/bin/sh\ntouch backup-was-called\n")
            backup.chmod(0o755)
            (root / "compose.yml").touch()
            rendered = root / "render.json"
            rendered.write_text(json.dumps(config()))
            git("add", ".")
            git("commit", "-m", "installed configuration")
            git("tag", "v1.1.0")
            before = git("rev-parse", "HEAD")
            git("switch", "-c", "release")
            rendered.write_text(json.dumps(config({"ipv4_address": "192.0.2.10"})))
            git("commit", "-am", "unsafe release configuration")
            git("tag", "v1.2.0")
            git("switch", "installed")
            env = "COMPOSE_FILE=compose.yml:compose.ghcr.yml\nSEKVYR_IMAGE_TAG=1.1.0\n"
            (root / ".env").write_text(env)
            docker = root / "docker"
            docker.write_text('''#!/bin/sh
case "$*" in
    'compose ps') exit 0;;
    'compose config --format json') cat render.json;;
    'compose config backend frontend') printf 'services:\n  backend:\n    image: backend:1.2.0\n  frontend:\n    image: frontend:1.2.0\n';;
    'compose pull backend frontend') touch pull-was-called;;
    'compose up '*) touch start-was-called; exit 99;;
    *) exit 99;;
esac
''')
            docker.chmod(0o755)
            result = subprocess.run(["sh", str(OPS / "update.sh"), "v1.2.0"], cwd=root, capture_output=True,
                                    timeout=10, env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                                                     "SEKVYR_APP": str(root), "SEKVYR_LANG": "en"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"Restored the previous checkout", result.stderr)
            self.assertEqual(git("rev-parse", "HEAD"), before)
            self.assertEqual(git("branch", "--show-current"), "installed")
            self.assertEqual((root / ".env").read_text(), env)
            self.assertTrue((root / "backup-was-called").exists())
            self.assertFalse((root / "start-was-called").exists())
