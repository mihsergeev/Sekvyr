"""Offline source/ownership guards. These do not claim a live E2E result."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import uuid

HERE = Path(__file__).resolve().parent
for directory in (HERE.parent, HERE.parent / "stage7", HERE.parent / "stage6"):
    if str(directory) not in sys.path:
        sys.path.append(str(directory))

from stage8 import provision_adapter as adapter
from stage8.provision_application import CLIApplication
from stage8.provision_live import LiveCLIProvider, complete_chain_reader


class FakeBundle:
    def __init__(self, values):
        self.values = values
    def value(self, name):
        return copy.deepcopy(self.values[name])
    def raw(self, name):
        value = self.values[name]
        return value if isinstance(value, bytes) else adapter.canonical(value)


class AdapterGuards(unittest.TestCase):
    def test_strict_parser_rejects_ambiguous_input_without_echo(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":"\\ud800"}',
                    b'\xef\xbb\xbf{}', b'{} {}', b'{"x":-1}', b'{"x":9007199254740992}'):
            with self.subTest(raw_size=len(raw)), self.assertRaises(adapter.ProvisionError):
                adapter.strict(raw)

    def test_paths_and_counters_cannot_be_aliased(self):
        for path in ("../outside", "/outside", "a//b", "a/./b", "a\\b", "a\x00b"):
            with self.assertRaises(adapter.ProvisionError): adapter.SecureRoot.parts(path)
        for number in (True, 1, "01", "1.0", "-1", "18446744073709551616"):
            with self.assertRaises(adapter.ProvisionError): adapter.counter(number)

    def test_bundle_will_not_read_arbitrary_name_or_changed_artifact(self):
        raw = b'{"public":"ciphertext"}'
        files = SimpleNamespace(read=Mock(return_value=raw))
        bundle = adapter.Bundle(files, "outputs/one", {"envelope.json": adapter.digest(raw)}, "a" * 64)
        self.assertEqual(bundle.raw("envelope.json"), raw)
        with self.assertRaises(adapter.ProvisionError): bundle.raw("../../keys/admin.pem")
        files.read.return_value = raw + b" "
        with self.assertRaises(adapter.ProvisionError): bundle.raw("envelope.json")
        self.assertNotIn("ciphertext", repr(bundle))

    def test_chain_registration_cannot_be_replaced_by_incoming_authority(self):
        provider = adapter.CLIProvider.__new__(adapter.CLIProvider)
        provider.files = SimpleNamespace(read=Mock(return_value=b"{}"))
        provider._profile_hash = "a" * 64
        with self.assertRaises(adapter.ProvisionError):
            provider._chain_guard({"registration_file": "incoming.json", "records_file": "records", "expected_cursor": {}})

    def test_commit_cannot_rebase_saved_candidate(self):
        bridge = LiveCLIProvider.__new__(LiveCLIProvider)
        bridge.current = Mock(return_value={"cursor": {"journal_sequence": "2", "record_hash": "b" * 64}})
        bridge.c = SimpleNamespace(panel=SimpleNamespace(owner_request=Mock(), witness_client=SimpleNamespace(request=Mock())))
        bundle = FakeBundle({"record.json": {"journal_sequence": "2", "previous_record_hash": "a" * 64}})
        with self.assertRaises(adapter.ProvisionError):
            bridge.commit_snapshot(bundle, {"sequence": "1", "envelope_hash": "c" * 64}, {"journal_sequence": "2", "record_hash": "b" * 64})
        bridge.current.assert_not_called()
        bridge.c.panel.owner_request.assert_not_called()
        bridge.c.panel.witness_client.request.assert_not_called()

    def test_stale_cursor_fails_before_staging(self):
        bridge = LiveCLIProvider.__new__(LiveCLIProvider)
        bridge.current = Mock(return_value={"cursor": {"journal_sequence": "4", "record_hash": "b" * 64}})
        bridge.c = SimpleNamespace(panel=SimpleNamespace(owner_request=Mock(), witness_client=SimpleNamespace(request=Mock())))
        bundle = FakeBundle({"record.json": {"journal_sequence": "2", "previous_record_hash": "a" * 64}})
        with self.assertRaises(adapter.ProvisionError):
            bridge.commit_snapshot(bundle, {}, {"journal_sequence": "1", "record_hash": "a" * 64})
        bridge.c.panel.owner_request.assert_not_called()

    def test_transport_exception_cannot_echo_fixture_secret(self):
        bridge = LiveCLIProvider.__new__(LiveCLIProvider)
        bridge.c = SimpleNamespace(current=Mock(side_effect=RuntimeError("synthetic-sensitive-canary")))
        with self.assertRaises(adapter.ProvisionError) as error:
            bridge.current()
        self.assertNotIn("synthetic-sensitive-canary", str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)

    def test_current_metadata_never_replaces_known_keys_or_accepts_numeric_alias(self):
        bridge = LiveCLIProvider.__new__(LiveCLIProvider)
        bridge.provider = SimpleNamespace(scope={"log_id": str(uuid.uuid4())}, registration={"genesis_hash": "a" * 64},
            authority={"revision": "1", "admin_key": {"key_id": "public-known-key"}})
        current = {"scope": bridge.provider.scope, "genesis_hash": "a" * 64,
            "authority": {"revision": "2", "admin_key": {"key_id": "public-known-key"}},
            "cursor": {"journal_sequence": "3", "record_hash": "b" * 64}, "snapshot": {"sequence": "1"}}
        bridge.c = SimpleNamespace(current=lambda: copy.deepcopy(current))
        self.assertEqual(bridge.current(), current)
        current["authority"]["admin_key"]["key_id"] = "untrusted-incoming-key"
        with self.assertRaises(adapter.ProvisionError): bridge.current()
        current["authority"]["admin_key"]["key_id"] = "public-known-key"
        current["authority"]["revision"] = True
        with self.assertRaises(adapter.ProvisionError): bridge.current()

    def test_application_cannot_adopt_saved_context(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "private").mkdir()
            (task / "private" / "application-context.json").write_text("{}")
            with self.assertRaises(adapter.ProvisionError):
                CLIApplication(SimpleNamespace(task=task), None)

    def test_legacy_python_recovery_signer_cannot_be_used_as_fallback(self):
        application = CLIApplication.__new__(CLIApplication)
        with self.assertRaises(adapter.ProvisionError): application.recovery_plan({})


class CompleteJournalGuards(unittest.TestCase):
    def setUp(self):
        self.log, self.nonce = str(uuid.uuid4()), "public-nonce"
        self.cursor = {"journal_sequence": "0", "record_hash": "a" * 64}
        self.begin = {"format": "sekvyr-journal-stream-begin-v1", "nonce": self.nonce, "count": 1, "last_record_hash": "a" * 64}
        self.end = dict(self.begin, format="sekvyr-journal-stream-end-v1")
        self.slot = {"sequence": "0", "receipt": {}, "record": {"log_id": self.log, "journal_sequence": "0"}}

    def read(self, begin=None, slots=None, end=None):
        raw = b"\n".join(adapter.canonical(value) for value in [begin or self.begin, *(slots or [self.slot]), end or self.end]) + b"\n"
        client = SimpleNamespace(journal=lambda log: (self.nonce, (200, raw, {})))
        return complete_chain_reader(client, self.log, lambda: {"scope": {"log_id": self.log}, "cursor": self.cursor})()

    def test_transport_returns_complete_records_but_does_not_claim_signature_authority(self):
        records, cursor = self.read()
        self.assertEqual(records, [self.slot["record"]])
        self.assertEqual(cursor, self.cursor)

    def test_nonce_count_unknown_fields_and_order_are_closed(self):
        for begin, slots, end in (
            (dict(self.begin, nonce="different"), None, None),
            (dict(self.begin, count=True), None, None),
            (None, None, dict(self.end, count=True)),
            (dict(self.begin, unexpected="value"), None, None),
            (None, [dict(self.slot, sequence="1")], None),
            (None, [self.slot, self.slot], None),
            (None, None, dict(self.end, last_record_hash="b" * 64)),
        ):
            with self.assertRaises(adapter.ProvisionError): self.read(begin, slots, end)


class TrustReservationGuards(unittest.TestCase):
    def setUp(self):
        self.app = CLIApplication.__new__(CLIApplication)
        self.app.namespace = "trial-apps"
        self.app.trust_name, self.app.state_name, self.app.node_secret_name = "operator-trust", "operator-state", "operator-node"
        self.app.cli_trust_complete = False
        self.app.namespace_guard = Mock()
        self.patch_calls = []
        self.uid, self.node_uid = str(uuid.uuid4()), str(uuid.uuid4())
        self.trust = {"metadata": {"uid": self.uid, "resourceVersion": "5"}, "type": "Opaque", "immutable": False, "data": {}}
        self.app._cli_trust_reservation = copy.deepcopy(self.trust)
        self.config = {"identityKeySecret": {"uid": self.node_uid}}
        marker = adapter.canonical({"installationID": str(uuid.uuid4()), "bootstrapGeneration": 1})
        self.bundle = FakeBundle({"installation.json": self.config, "trust.json": {"public": "CLI-generated-trust"}, "state-marker.json": marker})
        self.secrets = {self.app.trust_name: self.trust,
            self.app.node_secret_name: {"metadata": {"uid": self.node_uid}, "immutable": True},
            self.app.state_name: {"data": {"installation.json": base64.b64encode(marker).decode()}}}
        self.app.get = lambda kind, name: copy.deepcopy(self.secrets[name])
        def kube(*args, data=None):
            if args[0] == "get" and args[1] == "deployment": return SimpleNamespace(stdout="")
            if args[0] == "get" and args[1] == "pods": return SimpleNamespace(stdout='{"items":[]}')
            self.patch_calls.append((args, data))
            self.assertEqual(args[:3], ("patch", "secret", self.app.trust_name))
            self.assertIn("--patch-file=/dev/stdin", args)
            self.assertNotIn("-p", args)
            operations = adapter.strict(data.encode())
            self.assertEqual(operations[:2], [{"op": "test", "path": "/metadata/uid", "value": self.uid},
                {"op": "test", "path": "/metadata/resourceVersion", "value": "5"}])
            self.assertNotIn("CLI-generated-trust", " ".join(args))
            self.trust.update(data=operations[2]["value"], immutable=True)
            self.trust["metadata"]["resourceVersion"] = "6"
            return SimpleNamespace(stdout="{}")
        self.app.cluster = SimpleNamespace(kube=kube)

    def test_exact_reserved_uid_rv_and_cli_bytes_are_installed_immutable(self):
        result = self.app.populate_cli_trust(self.bundle, self.config)
        self.assertTrue(result["cliTrustInstalledImmutable"])
        self.assertTrue(self.app.cli_trust_complete)
        self.assertEqual(len(self.patch_calls), 1)
        self.assertEqual(base64.b64decode(self.trust["data"]["trust.json"]), self.bundle.raw("trust.json"))
        with self.assertRaises(adapter.ProvisionError): self.app.populate_cli_trust(self.bundle, self.config)
        self.assertEqual(len(self.patch_calls), 1)

    def test_wrong_uid_rv_or_nonempty_reservation_never_patched(self):
        original = copy.deepcopy(self.trust)
        for change in (lambda: self.trust["metadata"].update(uid=str(uuid.uuid4())),
                       lambda: self.trust["metadata"].update(resourceVersion="7"),
                       lambda: self.trust.update(immutable=True),
                       lambda: self.trust.update(data={"foreign": "value"})):
            self.trust.clear(); self.trust.update(copy.deepcopy(original)); change()
            with self.assertRaises(adapter.ProvisionError): self.app.populate_cli_trust(self.bundle, self.config)
            self.assertFalse(self.patch_calls)

    def test_identity_must_already_be_immutable(self):
        self.secrets[self.app.node_secret_name]["immutable"] = False
        with self.assertRaises(adapter.ProvisionError): self.app.populate_cli_trust(self.bundle, self.config)
        self.assertFalse(self.patch_calls)

    def test_pods_or_even_stopped_existing_runtime_deployments_deny_population(self):
        self.app.cluster.kube = Mock(return_value=SimpleNamespace(stdout='{"spec":{"replicas":0}}'))
        with self.assertRaises(adapter.ProvisionError): self.app.populate_cli_trust(self.bundle, self.config)
        self.assertFalse(self.patch_calls)


if __name__ == "__main__":
    unittest.main()
