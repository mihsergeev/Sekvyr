"""First-publish hook ordering without Helm, networking or panel actions."""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
from plain_cases import PlainCases


class InitialHookGuards(unittest.TestCase):
    def setUp(self):
        self.events = []
        def event(label):
            return lambda *args, **kwargs: self.events.append((label, args, kwargs))
        self.cases = SimpleNamespace(installation=SimpleNamespace(prepare=event("prepare"),
            prepare_store=event("store"), install=event("install-captured")),
            apps=SimpleNamespace(create_env=event("env-zero"), create_volume=event("volume-zero")),
            env_name="plain-env-app", volume_name="plain-volume-app", target_name="plain-runtime-env")
        def tail():
            self.events.append(("publish-and-app-start", (), {}))
            return "synthetic-tail-result"
        self.cases.initial_after_install = Mock(side_effect=tail)

    def test_hook_only_after_captured_install_before_any_publish_or_start(self):
        def hook(same_cases):
            self.assertIs(same_cases, self.cases)
            self.assertEqual([value[0] for value in self.events], ["prepare", "env-zero", "volume-zero", "store", "install-captured"])
            self.cases.initial_after_install.assert_not_called()
            self.events.append(("reviewed-network-paths", (), {}))
        self.assertEqual(PlainCases.initial(self.cases, hook), "synthetic-tail-result")
        self.assertEqual([value[0] for value in self.events], ["prepare", "env-zero", "volume-zero", "store",
            "install-captured", "reviewed-network-paths", "publish-and-app-start"])
        self.assertEqual(self.events[1][2], {"replicas": 0})
        self.assertEqual(self.events[2][2], {"replicas": 0})

    def test_hook_failure_never_publishes_or_starts_apps(self):
        def fail(same_cases):
            raise RuntimeError("Synthetic network precondition failed")
        with self.assertRaisesRegex(RuntimeError, "precondition failed"):
            PlainCases.initial(self.cases, fail)
        self.cases.initial_after_install.assert_not_called()
        self.assertEqual([value[0] for value in self.events], ["prepare", "env-zero", "volume-zero", "store", "install-captured"])

    def test_default_legacy_order_is_unchanged(self):
        self.assertEqual(PlainCases.initial(self.cases), "synthetic-tail-result")
        self.assertEqual([value[0] for value in self.events], ["prepare", "env-zero", "volume-zero", "store",
            "install-captured", "publish-and-app-start"])

    def test_noncallable_hook_fails_before_fixture_mutation(self):
        with self.assertRaisesRegex(RuntimeError, "must be callable"):
            PlainCases.initial(self.cases, {"not": "callable"})
        self.assertEqual(self.events, [])
        self.cases.initial_after_install.assert_not_called()


if __name__ == "__main__":
    unittest.main()
