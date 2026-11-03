"""Source-only CLI orchestration guards; no subprocess, network or cluster."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fixture import canonical
from stage8 import cli_coordinator as cc, cli_e2e_cases as ce, profiles
from stage8.provision_adapter import CLIProvider, ProvisionError
from stage8.provision_live import LiveCLIProvider, complete_chain_reader
from stage8.test_profiles import SYNTHETIC

CURSOR0 = {"journal_sequence": "0", "record_hash": "a" * 64}
CURSOR1 = {"journal_sequence": "1", "record_hash": "b" * 64}
CURSOR2 = {"journal_sequence": "2", "record_hash": "c" * 64}
SNAP = {"sequence": "1", "envelope_hash": "d" * 64}
SCOPE = {"log_id": "public-synthetic-log"}

class Bundle:
    def __init__(self, **outputs):
        self.outputs = outputs
    def raw(self, name):
        return self.outputs[name]
    def value(self, name):
        return json.loads(self.raw(name))


class NativeBridgeGuards(unittest.TestCase):
    def test_runtime_publication_keeps_verified_checkpoint_epochs(self):
        epochs = {"read_key_epoch": "7", "publisher_policy_epoch": "9"}
        bundle = Bundle(**{"envelope.json": canonical({"body": {"header": epochs}})})
        pins = SimpleNamespace(scope=SCOPE, registration={"genesis_hash": CURSOR0["record_hash"]})
        bridge = LiveCLIProvider(SimpleNamespace(protocol=pins), pins, Mock(), Mock())
        bridge.prepare_snapshot = Mock(return_value=(bundle, SNAP, CURSOR1))
        bridge.commit_snapshot = Mock()
        bridge.grant_reader = Mock()
        self.assertEqual(bridge.publish("generation", "demo", label="candidate"), {**SNAP, **epochs})
        bridge.commit_snapshot.assert_called_once_with(bundle, SNAP, CURSOR1)
        bridge.grant_reader.assert_called_once_with(bundle)

    def test_initialize_uses_fresh_post_enrollment_records_and_exact_cli_artifacts(self):
        for stream_hash in (CURSOR2["record_hash"], CURSOR1["record_hash"]):
            with self.subTest(stream_hash=stream_hash):
                registration = {"genesis_hash": CURSOR0["record_hash"]}
                protocol = SimpleNamespace(scope=SCOPE, registration=registration, installation_id="fixture-installation")
                app = SimpleNamespace(protocol=protocol, cli_trust_complete=True, generation=1,
                    state_name="fixture-state", binding={}, get=Mock(return_value={"metadata": {"uid": "fixture-state-uid"}}),
                    start_application_after_initialize=Mock())
                current = {"scope": SCOPE, "genesis_hash": registration["genesis_hash"],
                    "authority": {"revision": "2"}, "cursor": CURSOR2, "snapshot": SNAP}
                coordinator = SimpleNamespace(protocol=protocol, app=app, current=Mock(return_value=current))
                provider = Mock(scope=SCOPE, registration=registration, authority={"revision": "1"}, node_fingerprint="fixture-node")
                chain = {"expected_cursor": CURSOR2}
                provider.freeze_chain.return_value = chain
                plan = {"body": {"synthetic": True}}
                provider.recovery.return_value = Bundle(**{"plan.json": canonical(plan)})
                records = [{"journal_sequence": str(i), "log_id": SCOPE["log_id"]} for i in range(3)]
                frame = {"nonce": "fixture-nonce", "count": len(records), "last_record_hash": stream_hash}
                rows = [{"format": "sekvyr-journal-stream-begin-v1", **frame},
                    *[{"sequence": str(i), "receipt": {}, "record": r} for i, r in enumerate(records)],
                    {"format": "sekvyr-journal-stream-end-v1", **frame}]
                gateway = Mock()
                gateway.journal.return_value = (frame["nonce"], (200, b"\n".join(map(canonical, rows)), {}))
                native = Mock(return_value={"checkpointRecoveryComplete": True})
                bridge = LiveCLIProvider(coordinator, provider,
                    complete_chain_reader(gateway, SCOPE["log_id"], coordinator.current), native)
                installation = {"identityKeySecret": {"uid": "fixture-identity"}, "trustBundleSecret": {"uid": "fixture-trust"}}
                normalized = {"binding": {"identity": "fixture-binding"}}
                bridge.uid_receipts = Mock(return_value=normalized)
                bridge.bootstrap_bundle = Bundle(**{"receipts.json": canonical(normalized), "installation.json": canonical(installation)})
                bridge.snapshots[SNAP["envelope_hash"]] = Bundle(**{"envelope.json": b"fixture-cli-envelope",
                    "reader-wrap.json": b"fixture-cli-wrap"})
                if stream_hash != CURSOR2["record_hash"]:
                    with self.assertRaises(ProvisionError):
                        bridge.initialize("recovery", installation)
                    provider.recovery.assert_not_called()
                    native.assert_not_called()
                    app.start_application_after_initialize.assert_not_called()
                    continue
                self.assertTrue(bridge.initialize("recovery", installation)["cliSignedInitializeConsumedByNativeRecovery"])
                provider.freeze_chain.assert_called_once_with("recovery-before", records, CURSOR2)
                recovery_body = provider.recovery.call_args.args[-1]
                self.assertEqual(recovery_body["cursor"], CURSOR2)
                self.assertEqual(recovery_body["snapshot"], SNAP)
                self.assertFalse(recovery_body["allow_rollout"])
                native.assert_called_once_with(plan, b"fixture-cli-envelope", b"fixture-cli-wrap", installation)
                app.start_application_after_initialize.assert_called_once_with()

class TempTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.task = Path(temp.name)
        self.private = self.task / "private"
        self.private.mkdir()
        pin = patch.object(profiles, "REVIEWED_ARTIFACTS", SYNTHETIC)
        pin.start()
        self.addCleanup(pin.stop)

class GenesisGuards(TempTest):
    def genesis(self):
        record = {"genesis": {"body": {"scope": SCOPE}}}
        registration = {"log_id": SCOPE["log_id"], "genesis_hash": CURSOR0["record_hash"]}
        original = canonical(record)
        bundle = Bundle(**{"record.json": original, "registration.json": canonical(registration),
            "records.json": canonical([record])})
        protocol = SimpleNamespace(genesis_record=record, registration=registration, scope=SCOPE)
        owner = SimpleNamespace(task=self.task, raw=b"synthetic-capability", guard=Mock())
        provider = Mock(spec=CLIProvider)
        provider.genesis.return_value = bundle
        gateway = Mock()
        def stream(slots, hash):
            common = {"nonce": "public-fixture-nonce", "count": len(slots), "last_record_hash": hash}
            begin = canonical(dict(common, format="sekvyr-journal-stream-begin-v1"))
            end = canonical(dict(common, format="sekvyr-journal-stream-end-v1"))
            return common["nonce"], (200, b"\n".join([begin, *map(canonical, slots), end]) + b"\n", {})
        empty = stream([], "0" * 64)
        full = stream([{"record": record}], registration["genesis_hash"])
        gateway.journal.side_effect = [empty, full]
        gateway.append.return_value = (200, canonical({"mode": "COMPLIANCE", "version_id": "public-opaque"}), {})
        return owner, protocol, provider, gateway, original, full

    def call(self, owner, protocol, provider, gateway):
        with patch.object(cc, "owned_capability", return_value=owner), \
                patch.object(cc.ProtocolAuthority, "load", return_value=protocol), \
                patch.object(cc, "new_provider", return_value=provider):
            return cc.prepare_main_genesis(self.task, profile="kind-1.37.0", gateway_client=gateway)

    def test_actual_append_parameter_is_saved_cli_bytes_and_second_attempt_never_reuses(self):
        owner, protocol, provider, gateway, original, _ = self.genesis()
        returned, facts = self.call(owner, protocol, provider, gateway)
        self.assertIs(returned, provider)
        self.assertIs(gateway.append.call_args.args[2], original)
        self.assertTrue(facts["gatewayConsumedCLIRecordBytes"])
        with self.assertRaises(ProvisionError): self.call(owner, protocol, provider, gateway)
        gateway.append.assert_called_once()
        provider.genesis.assert_called_once()

    def test_existing_main_log_is_not_adopted_even_if_bytes_are_the_same(self):
        owner, protocol, provider, gateway, _, full = self.genesis()
        gateway.journal.side_effect = [full]
        with self.assertRaises(ProvisionError): self.call(owner, protocol, provider, gateway)
        gateway.append.assert_not_called()
        provider.close.assert_called_once()

    def test_mismatched_cli_genesis_or_registration_cannot_reach_gateway(self):
        owner, protocol, provider, gateway, _, _ = self.genesis()
        provider.genesis.return_value.outputs["registration.json"] = b'{}'
        with self.assertRaises(ProvisionError): self.call(owner, protocol, provider, gateway)
        gateway.journal.assert_not_called()
        gateway.append.assert_not_called()

class CoordinatorGuards(TempTest):
    def test_context_and_provider_mismatch_refuse_before_forward_or_instance_receipt(self):
        owner = SimpleNamespace(task=self.task, raw=b"public-capability")
        with patch.object(cc, "owned_capability", return_value=owner), \
                patch.object(cc, "Forward", side_effect=AssertionError("No network")), \
                patch.object(cc.ProtocolAuthority, "load", return_value=SimpleNamespace()):
            with self.assertRaises(ProvisionError):
                cc.CLICoordinator(self.task, profile="kind-1.34.11", provider=object())
            (self.private / "application-context.json").write_bytes(b"{}")
            with self.assertRaises(ProvisionError):
                cc.CLICoordinator(self.task, profile="kind-1.34.11", provider=object())
        self.assertFalse((self.private / "stage8-coordinator-instance.json").exists())

    def test_private_constructor_scope_keeps_legacy_factories_and_binds_native_recovery(self):
        cluster = SimpleNamespace(task=self.task, fixture={"namespaces": {"panel": "public-panel", "gateway": "public-gateway",
            "witness": "public-witness"}}, namespace_pins=lambda: {"public-panel": "public-uid"}, pins=self.private / "creation-uids")
        protocol = SimpleNamespace(scope=SCOPE, registration={}, authority={}, node_public=b"public-node",
            node_fingerprint="public-fingerprint", panel_origin="https://panel.example.invalid")
        provider = Mock(spec=CLIProvider)
        provider.scope, provider.registration, provider.authority = protocol.scope, protocol.registration, protocol.authority
        provider.node_public, provider.node_fingerprint, provider.panel_origin = protocol.node_public, protocol.node_fingerprint, protocol.panel_origin
        provider.files = SimpleNamespace(path=self.private / "provision-stage8")
        provider.cli = SimpleNamespace(sha256=SYNTHETIC["provision_sha256"])
        owner = SimpleNamespace(task=self.task, raw=b"public-capability", guard=Mock())
        provider._stage8_genesis_owner = (self.task, "kind-1.37.0", cc.digest(owner.raw))
        old_app, old_panel = cc.legacy.Application, cc.legacy.TrialPanel
        native, app = Mock(return_value={"checkpointRecoveryComplete": True}), Mock()
        witness_forward, gateway_forward = Mock(origin="https://witness.example.invalid"), Mock(origin="https://gateway.example.invalid")
        with patch.object(cc, "owned_capability", return_value=owner), patch.object(cc, "verified_cli"), \
                patch.object(cc.legacy, "safe_task", return_value=self.task), patch.object(cc.legacy, "BudgetCluster", return_value=cluster), \
                patch.object(cc.ProtocolAuthority, "load", return_value=protocol), patch.object(cc, "CLIApplication", return_value=app), \
                patch.object(cc, "bind", return_value=native) as bind, patch.object(cc.legacy, "Forward", return_value=witness_forward) as wf, \
                patch.object(cc, "Forward", return_value=gateway_forward) as gf, patch.object(cc.legacy, "JournalClient"), \
                patch.object(cc, "JournalClient"), patch.object(cc.legacy.Coordinator, "materials", return_value={}):
            c = cc.CLICoordinator(self.task, profile="kind-1.37.0", provider=provider)
            self.assertIs(c.app, app)
            self.assertIsInstance(c.panel, cc.CLITrialPanel)
            bind.assert_called_once_with(c.panel, "kind-1.37.0")
            c.panel.recover({"plan": 1}, b"envelope", b"wrap", {"installation": 1})
            native.assert_called_once_with({"plan": 1}, b"envelope", b"wrap", {"installation": 1})
            with self.assertRaises(ProvisionError): c.panel.publish("generation", "demo")
            with self.assertRaises(ProvisionError): cc.CLICoordinator(self.task, profile="kind-1.37.0", provider=provider)
            wf.assert_called_once()
            gf.assert_called_once()
            c.close()
        provider.close.assert_called_once()
        witness_forward.close.assert_called_once()
        gateway_forward.close.assert_called_once()
        self.assertIs(cc.legacy.Application, old_app)
        self.assertIs(cc.legacy.TrialPanel, old_panel)

    def test_publication_saved_labels_and_failure_never_retry_or_rebase(self):
        c = Mock(spec=cc.CLICoordinator)
        c.private, c.cli_active, c._publish_index, c._publish_pending = self.private, True, 0, False
        c.capability, c.bridge = Mock(), Mock()
        c.bridge.publish.side_effect = [SNAP, ProvisionError("CLIJournalChangedBeforeCommit")]
        self.assertEqual(cc.CLICoordinator.publish(c, "g1", "v1"), SNAP)
        with self.assertRaises(ProvisionError): cc.CLICoordinator.publish(c, "g2", "v2")
        with self.assertRaises(ProvisionError): cc.CLICoordinator.publish(c, "g2", "v2")
        self.assertEqual([call.kwargs["label"] for call in c.bridge.publish.call_args_list],
            ["runtime-publish-1", "runtime-publish-2"])
        self.assertTrue((self.private / "runtime-publish-2-request.json").is_file())
        self.assertFalse((self.private / "runtime-publish-2-committed.json").exists())

class CaseOrdering(TempTest):
    def case(self):
        c = Mock(spec=cc.CLICoordinator)
        c.task, c.private, c.profile, c.cli_active = self.task, self.private, "kind-1.37.0", False
        c.capability, c.bridge, c.app, c.panel, c.cluster = Mock(), Mock(), Mock(), Mock(), Mock()
        c.protocol = SimpleNamespace(scope=SCOPE, genesis_hash=CURSOR0["record_hash"], registration={"minimum_cursor": CURSOR0},
            snapshot=Mock(side_effect=AssertionError("Python signer forbidden")))
        c.panel_origin, c.witness_origin, c.gateway_origin = "panel", "witness", "gateway"
        c.materials.return_value = {}
        app = c.app
        app.namespace, app.created, app.fencer_tls_secret_name, app.cli_trust_complete = "public-apps", {}, "fencer-tls", False
        app.get.return_value = {"metadata": {"uid": "public-fixture"}}
        app.recovery_plan.side_effect = AssertionError("Python recovery signer forbidden")
        c.cluster.kube.return_value.stdout = '{"status":{"userInfo":{"username":"public-fixture"}}}'
        (self.task / "infrastructure-parameters.json").write_bytes(canonical({"node_name": "public-fixture"}))
        (self.private / "journal-ca.crt").write_bytes(b"synthetic-public-ca")
        install = {"namespace": app.namespace, "ha": {"trial": True}}
        lifecycle = Mock()
        manifest = {"kind": "ConfigMap", "metadata": {"namespace": app.namespace}, "immutable": True,
            "data": {"installation.json": canonical(install).decode()}}
        lifecycle.render.return_value = ([manifest], None)
        values = {"image": {"digest": SYNTHETIC["operator_image"]}}
        state = {"scope": SCOPE, "genesis_hash": CURSOR0["record_hash"], "cursor": CURSOR0,
            "snapshot": {"sequence": "0"}}
        events = []
        bundle = Bundle(**{"envelope.json": b"saved-cli-envelope"})
        c.bridge.current.side_effect = lambda: copy.deepcopy(state)
        c.bridge.prepare_snapshot.side_effect = lambda *a: (events.append("cli-snapshot") or (bundle, SNAP, CURSOR0))
        app.prepare.side_effect = lambda *a: events.append("reserve")
        c.panel.bootstrap.side_effect = lambda: events.append("panel-bootstrap")
        def commit(saved, snapshot, expected):
            self.assertIs(saved, bundle); self.assertEqual(expected, CURSOR0)
            events.append("commit"); state.update(cursor=CURSOR1, snapshot=SNAP)
            return snapshot
        c.bridge.commit_snapshot.side_effect = commit
        c.bridge.grant_reader.side_effect = lambda saved: self.assertIs(saved, bundle) or events.append("grant")
        def bootstrap(label, actual):
            self.assertEqual(actual, install); events.append("cli-trust"); app.cli_trust_complete = True
            return {"cliBootstrapConsumed": True}
        c.bridge.bootstrap.side_effect = bootstrap
        c.bridge.enroll.side_effect = lambda label: (events.append("cli-enroll") or {"cliSignedEnrollmentCommitted": True})
        c.bridge.initialize.side_effect = lambda label, cfg: (events.append("cli-native-init") or {"cliSignedInitializeConsumedByNativeRecovery": True})
        c.enable_cli_publications.side_effect = lambda cfg: events.append("arm")
        def leaf(task, ca, name, role, hosts):
            self.assertEqual(hosts, ["stage6-fencer.public-apps.svc", "stage6-fencer.public-apps.svc.cluster.local", "localhost"])
            events.append("tls-both-sans")
            for extension in ("crt", "key"): (self.private / (name + "." + extension)).write_bytes(b"synthetic-fixture")
        for replacement in (patch.object(ce, "issue_leaf", side_effect=leaf),
                patch.object(ce, "reviewed_values", return_value=values), patch.object(ce, "HelmLifecycle", return_value=lifecycle)):
            replacement.start(); self.addCleanup(replacement.stop)
        case = ce.CLIE2E2Cases(c, SYNTHETIC["operator_image"], "unused", "unused")
        case.proof = Mock()
        return case, c, lifecycle, state, events

    def test_order_keeps_runtime_absent_and_never_uses_old_signer(self):
        e, c, lifecycle, _, events = self.case()
        e.prepare(before_first_publish=lambda prepared: events.append("explicit-network"))
        e.initialize()
        self.assertEqual(events, ["cli-snapshot", "tls-both-sans", "reserve", "explicit-network", "panel-bootstrap",
            "commit", "grant", "cli-trust", "cli-enroll", "cli-native-init", "arm"])
        self.assertTrue(e.initialized)
        lifecycle.install.assert_not_called()
        c.protocol.snapshot.assert_not_called()
        c.panel.publish_sealed.assert_not_called()
        c.panel.offline_export.assert_not_called()
        c.app.recovery_plan.assert_not_called()

    def test_network_hook_failure_prevents_publish_and_duplicate_prepare_is_closed(self):
        e, c, lifecycle, _, _ = self.case()
        hook = Mock(side_effect=RuntimeError("synthetic-private-canary"))
        with self.assertRaises(ProvisionError) as failure: e.prepare(before_first_publish=hook)
        self.assertNotIn("synthetic-private-canary", str(failure.exception))
        c.panel.bootstrap.assert_not_called()
        c.bridge.commit_snapshot.assert_not_called()
        lifecycle.install.assert_not_called()
        with self.assertRaises(ProvisionError): e.prepare()
        c.bridge.prepare_snapshot.assert_called_once()

    def test_cursor_advance_prevents_trust_enrollment_and_native_recovery(self):
        e, c, lifecycle, state, _ = self.case()
        e.prepare()
        state["cursor"] = CURSOR2
        with self.assertRaises(ProvisionError): e.initialize()
        c.bridge.bootstrap.assert_not_called()
        c.bridge.enroll.assert_not_called()
        c.bridge.initialize.assert_not_called()
        lifecycle.install.assert_not_called()

    def test_native_failure_cannot_arm_or_install_and_does_not_sign_again(self):
        e, c, lifecycle, _, _ = self.case()
        e.prepare()
        c.bridge.initialize.side_effect = ProvisionError("CLINativeRecoveryNotComplete")
        with self.assertRaises(ProvisionError): e.initialize()
        with self.assertRaises(ProvisionError): e.initialize()
        with self.assertRaises(RuntimeError): e.install()
        c.bridge.initialize.assert_called_once()
        c.enable_cli_publications.assert_not_called()
        lifecycle.install.assert_not_called()
