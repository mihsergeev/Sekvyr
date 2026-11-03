from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.append(str(Path(__file__).resolve().parents[1] / "stage6"))
import isolation_cases as isolation


class IsolationGuards(unittest.TestCase):
    def fixture(self, directory):
        def kube(*args, **kwargs):
            if args[:2] == ("create", "token"):
                return SimpleNamespace(stdout="synthetic-ephemeral-token")
            self.assertEqual(args[:2], ("auth", "can-i"))
            allowed = args[2:4] == ("get", "secret/plain-state") and args[5] == "isolated" and args[7] == "system:serviceaccount:isolated:plain-operator"
            return SimpleNamespace(returncode=0 if allowed else 1, stdout="yes" if allowed else "no")
        c = SimpleNamespace(private=directory, cluster=SimpleNamespace(kube=kube),
            app=SimpleNamespace(namespace="apps", state_name="operator-state", rbac_cases=lambda: {"operatorRBACTestedOperations": 14}),
            panel=SimpleNamespace(request=Mock(return_value=(401, {}))))
        provider = SimpleNamespace(routing=lambda: {"project": "main", "environment": "trial"})
        agent = SimpleNamespace(exchange=lambda token: object(), read=lambda *args: {},
            routing=lambda: {"project": "agent", "environment": "trial"}, assert_denied_source=Mock(return_value={"http": 403}))
        cases = SimpleNamespace(c=c, installation=SimpleNamespace(namespace="isolated", sa="plain-operator", state_name="plain-state"),
            provider=provider, agent_provider=agent, token=lambda: {"token": "synthetic-file-token"}, agent_selected={"generation": "generation", "demo": "demo"})
        own = SimpleNamespace(pins={}, reload_pins=lambda: None, create_service_account=Mock())
        return cases, SimpleNamespace(c=c, installed=True), own

    def execute(self, cases, e2e, own):
        with patch.object(isolation, "OwnedNamespace", return_value=own), patch.object(isolation, "write_private") as saved:
            result = isolation.run(cases, e2e)
            return result, saved

    def test_denials_and_namespace_sar_are_required(self):
        with TemporaryDirectory() as directory:
            cases, e2e, own = self.fixture(Path(directory))
            result, saved = self.execute(cases, e2e, own)
        self.assertEqual(result["liveRBACTestedOperations"], 18)
        self.assertFalse(result["panelMachineAuthorizationUIDBound"])
        self.assertFalse(result["packetIsolationClaimed"])
        own.create_service_account.assert_called_once_with("plain-operator")
        saved.assert_called_once()

    def test_cross_project_allow_cannot_be_reported_as_denial(self):
        with TemporaryDirectory() as directory:
            cases, e2e, own = self.fixture(Path(directory))
            cases.agent_provider.assert_denied_source.return_value = {"http": 200}
            with self.assertRaises(RuntimeError):
                self.execute(cases, e2e, own)
        own.create_service_account.assert_not_called()

    def test_same_namespace_is_not_isolation(self):
        with TemporaryDirectory() as directory:
            cases, e2e, own = self.fixture(Path(directory))
            cases.installation.namespace = "apps"
            with self.assertRaises(RuntimeError):
                self.execute(cases, e2e, own)

    def test_wrong_namespace_token_acceptance_cannot_pass(self):
        with TemporaryDirectory() as directory:
            cases, e2e, own = self.fixture(Path(directory))
            cases.c.panel.request.return_value = (200, {})
            with self.assertRaises(RuntimeError):
                self.execute(cases, e2e, own)


if __name__ == "__main__":
    unittest.main()
