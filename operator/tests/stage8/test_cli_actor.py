"""Actor phase recording and ordering tests without live services."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, call, patch

from stage8 import cli_actor
from stage8.provision_adapter import ProvisionError


class ActorTests(unittest.TestCase):
    def test_plain_must_reconcile_after_physical_panel_outage(self):
        plain, cases = Mock(), Mock()
        steps = Mock()
        steps.attach_mock(plain.installation.current, "plain_status")
        steps.plain_status.side_effect = [{"status": {"lastSuccessfulSyncTime": "before"}}, {"status": {}}]
        with patch.object(cli_actor, "dependency_outages", steps.outage), \
                patch.object(cli_actor, "wait", side_effect=lambda check, *, timeout: check()):
            cli_actor._panel_outage_then_plain_recovery(plain, cases)
        self.assertEqual(steps.mock_calls, [call.plain_status(), call.outage(cases, labels=("panel",)),
            call.plain_status(after_success="before")])

    def test_ha_final_is_limited_to_reviewed_full_kubernetes_profile(self):
        with patch.object(cli_actor, "owned_capability") as capability:
            with self.assertRaises(ProvisionError):
                cli_actor.run(Path("."), profile="kind-1.34.11", helm=None, chart=None,
                    ha_rendered=[], reviewed_ha_sha256="fixture-render", api_endpoints=[],
                    admission_sources=[], acceptance="ha-final")
            capability.assert_not_called()

    def test_interrupted_phase_remains_incomplete_and_run_cannot_be_reopened(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cli_actor, "_record",
                lambda path, value: cli_actor.write_private(path, cli_actor.canonical(value))):
            private = Path(directory)
            attempt = cli_actor.Attempt(private, "fixture-profile", "fixture-capability", "fixture-render", "full")
            publish = Mock(side_effect=RuntimeError("interrupted"))
            with self.assertRaises(RuntimeError):
                attempt.step("publish", publish)
            self.assertTrue((private / "stage8-cli-actor-01-publish-start.json").is_file())
            self.assertFalse((private / "stage8-cli-actor-01-publish-complete.json").exists())
            with self.assertRaises(FileExistsError):
                cli_actor.Attempt(private, "fixture-profile", "fixture-capability", "fixture-render", "full")
            publish.assert_called_once_with()

    def test_plain_hook_precedes_publication_and_ha_selector_mismatch_stops_run(self):
        calls = []
        plain = Mock()
        ha = Mock()
        ha.rendered = ["actual"]
        plain.initial.side_effect = lambda *, before_first_publish: (
            calls.append("plain-helm"), before_first_publish(plain), calls.append("plain-publish"))
        ha.prepare.side_effect = lambda *, before_first_publish: (
            before_first_publish(ha), calls.append("ha-publish"))
        coordinator = Mock()
        provider = Mock()
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            owner = SimpleNamespace(task=task, raw=b"fixture-owner", guard=Mock())
            (task / "private").mkdir()
            network = Mock()
            network._namespaces.return_value = ({"apps": "fixture-apps", "gateway": "fixture-gateway"}, {})
            network._sha.return_value = "fixture-render"
            network._render_selectors.side_effect = [{"operator": "expected"}, {"operator": "different"}]
            network.install.side_effect = lambda *args, **kwargs: calls.append("narrow-paths")
            with patch.multiple(cli_actor, network_paths=network, BudgetCluster=Mock(), Forward=Mock(return_value=MagicMock()),
                    clients=Mock(return_value={"admin": Mock()}), CLICoordinator=Mock(return_value=coordinator),
                    PlainCases=Mock(return_value=plain), CLIE2E2Cases=Mock(return_value=ha),
                    phase=Mock(), owned_capability=Mock(return_value=owner),
                    _initialize_auxiliary_logs=Mock(),
                    prepare_main_genesis=Mock(return_value=(provider, {})),
                    reviewed=Mock(return_value=(SimpleNamespace(name="fixture-profile"),
                        {"operator_image": "fixture-operator", "backend_image": "fixture-panel"})),
                    _record=lambda path, value: cli_actor.write_private(path, cli_actor.canonical(value))):
                with self.assertRaises(ProvisionError):
                    cli_actor.run(task, profile="fixture-profile", helm=None, chart=None,
                        ha_rendered=["reviewed"], reviewed_ha_sha256="fixture-render",
                        api_endpoints=[], admission_sources=[], acceptance="reduced")
            self.assertEqual(calls, ["plain-helm", "narrow-paths", "plain-publish"])
            ha.initialize.assert_not_called()
            coordinator.close.assert_called_once_with()
            self.assertFalse((task / "private" / "stage8-cli-actor-complete.json").exists())

    def test_auxiliary_log_cannot_alias_main_log(self):
        labels = ("duplicate-version", "delete-marker", "replica-cas")
        entries = {label: {"registration": {"log_id": label, "genesis_hash": "fixture"},
            "record": {"log_id": label, "journal_sequence": "0"}} for label in labels}
        entries["replica-cas"]["registration"]["log_id"] = "main"
        entries["replica-cas"]["record"]["log_id"] = "main"
        protocol = SimpleNamespace(scope={"log_id": "main"}, fault_logs=entries)
        gateway = Mock()
        with patch.object(cli_actor.ProtocolAuthority, "load", return_value=protocol), \
                patch.object(cli_actor, "record_hash", return_value="fixture"):
            with self.assertRaises(ProvisionError):
                cli_actor._initialize_auxiliary_logs(SimpleNamespace(task=Path(".")), gateway)
        self.assertEqual(gateway.mock_calls, [])

    def test_uninstall_does_not_credit_recreated_target(self):
        def target(uid):
            return {"metadata": {"uid": uid, "annotations": {cli_actor.REVISION: "fixture-revision"}},
                "data": {"fixture": "synthetic"}}

        uninstall = Mock()
        read = Mock(side_effect=[target("before"), target("after")])
        with self.assertRaises(ProvisionError):
            cli_actor._uninstall_preserving_target(read, uninstall)
        uninstall.assert_called_once_with()
