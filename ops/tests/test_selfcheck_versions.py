"""Version gates accept reviewed prereleases and reject missing declarations."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("sekvyr_selfcheck_versions", Path(__file__).resolve().parents[1] / "selfcheck.py")
selfcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selfcheck)

class VersionGate(unittest.TestCase):
    def check(self, version, changes=None):
        data = {
            "backend/pyproject.toml": f'version = "{version}"\n',
            "backend/app/config.py": f'    version: str = "{version}"\n',
            "frontend/package.json": f'  "version": "{version}",\n',
            "CHANGELOG.md": f'## [{version}] - Unreleased\n## [1.0.3] - 2026-10-31\n',
        }
        data.update(changes or {})
        selfcheck.PROBLEMS.clear()
        with patch.object(selfcheck, "read", side_effect=data.__getitem__):
            selfcheck.check_version()
        return list(selfcheck.PROBLEMS)

    def tearDown(self):
        selfcheck.PROBLEMS.clear()

    def test_stable_and_rc(self):
        for v in ("1.0.3", "1.1.0-rc.1", "0.1.0-rc.1", "1.1.0-rc.1+review.7"):
            with self.subTest(version=v):
                self.assertEqual(self.check(v), [])

    def test_invalid_or_all_missing_never_pass(self):
        for v in ("?", "", "1.0", "01.0.0", "1.1.0-rc.01", "1.1.0-", "v1.1.0", "1.1.0+", "1.1.0-rc 1"):
            with self.subTest(version=v):
                self.assertTrue(self.check(v))
        self.assertTrue(self.check("1.1.0-rc.1", {key: "" for key in ("backend/pyproject.toml", "backend/app/config.py", "frontend/package.json", "CHANGELOG.md")}))

    def test_missing_and_mismatched_declarations_fail(self):
        self.assertTrue(self.check("1.1.0-rc.1", {"backend/app/config.py": ""}))
        self.assertTrue(self.check("1.1.0-rc.1", {"frontend/package.json": '  "version": "1.0.3",\n'}))
        self.assertTrue(self.check("1.1.0-rc.1", {"CHANGELOG.md": "## [1.0.3] - 2026-10-31\n"}))

class OperatorVersionGate(unittest.TestCase):
    def setUp(self):
        self.v = "0.1.0-rc.1"
        self.data = {
            "operator/VERSION": self.v + "\n",
            "operator/charts/sekvyr-operator/Chart.yaml": f"version: {self.v}\nappVersion: {self.v}\n",
            "operator/Dockerfile": f"ARG VERSION={self.v}\n",
            "operator/internal/provision/types.go": f'const Version = "{self.v}"\n',
        }
        selfcheck.PROBLEMS.clear()
        self.addCleanup(selfcheck.PROBLEMS.clear)

    def run_gate(self):
        selfcheck.PROBLEMS.clear()
        with patch.object(selfcheck, "read", side_effect=self.data.__getitem__):
            selfcheck.check_operator_version()
        return list(selfcheck.PROBLEMS)

    def test_independent_operator_version_agrees(self):
        self.assertEqual(self.run_gate(), [])

    def test_each_missing_or_mismatched_component_blocks_candidate(self):
        for path in list(self.data):
            original = self.data[path]
            for bad in ("", original.replace(self.v, "0.1.0-stage7-trial")):
                with self.subTest(path=path, bad=bad):
                    self.data[path] = bad
                    self.assertTrue(self.run_gate())
            self.data[path] = original


if __name__ == "__main__":
    unittest.main()
