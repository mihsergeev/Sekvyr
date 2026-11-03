"""Local crypto/persistence checks; live rotation acceptance is separate."""

import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature, InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import TrialFixture, canonical
from protocol import ProtocolAuthority, domain, key_descriptor
from rotation_cases import (RotationCases, binary, decrypt_snapshot, load_protocol_version,
    save_protocol_version, saved_candidate, unwrap)


class RotationGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sekvyr-stage6.")
        self.addCleanup(self.directory.cleanup)
        self.task = Path(self.directory.name).resolve()
        TrialFixture(self.task)
        self.protocol = ProtocolAuthority(self.task)

    def test_versions_preserve_genesis_pin_but_rotate_exact_roles_and_epochs(self):
        parent = self.protocol
        registration = copy.deepcopy(parent.registration)
        genesis = copy.deepcopy(parent.genesis_record)
        for role in ("publisher", "read", "witness", "admin", "fencer", "node", "read"):
            path = self.task / "private" / ("version-" + str(len(list((self.task / "private").glob("version-*")))))
            value = save_protocol_version(path, parent, role)
            loaded = load_protocol_version(path, self.protocol)
            self.assertEqual(loaded.authority, value.authority)
            self.assertEqual(loaded.node_public, value.node_public)
            self.assertEqual(loaded.read_key, value.read_key)
            self.assertEqual(loaded.registration, registration)
            self.assertEqual(loaded.genesis_record, genesis)
            if role == "node":
                self.assertEqual(value.authority, parent.authority)
                self.assertNotEqual(value.node_fingerprint, parent.node_fingerprint)
            else:
                self.assertEqual(int(value.authority["revision"]), int(parent.authority["revision"]) + 1)
            parent = loaded
        self.assertEqual(parent.registration["admin_public_key"], key_descriptor(self.protocol.admin)["public_key"])
        self.assertNotEqual(parent.authority["admin_key"], key_descriptor(self.protocol.admin))

    def test_fresh_read_key_after_new_node_cryptographically_excludes_both_old_credentials(self):
        old = self.protocol
        new_node = save_protocol_version(self.task / "private" / "new-node", old, "node")
        current = save_protocol_version(self.task / "private" / "new-read", new_node, "read")
        wrapper = current.reader_wrap()
        self.assertEqual(unwrap(current, wrapper, current.node), current.read_key)
        with self.assertRaises(InvalidTag):
            unwrap(current, wrapper, old.node)
        envelope, _ = current.snapshot(2, "a" * 64, "public-canary", "public-demo", action="rotate-read-key")
        values = decrypt_snapshot(current, envelope, current.read_key)
        self.assertEqual(values["entries"], [{"path": "/runtime", "name": "DEMO_VALUE", "value": "public-demo"},
            {"path": "/runtime", "name": "GENERATION", "value": "public-canary"}])
        with self.assertRaises(InvalidTag):
            decrypt_snapshot(current, envelope, old.read_key)

    def test_publisher_signature_and_scope_are_checked_before_unwrap_or_snapshot_plaintext(self):
        current = save_protocol_version(self.task / "private" / "new-publisher", self.protocol, "publisher")
        wrapper = current.reader_wrap()
        with self.assertRaises(InvalidSignature):
            self.protocol.publisher.public_key().verify(binary(wrapper["signature"]),
                domain("sekvyr-e2e2/reader-wrap-sign/v1") + canonical(wrapper["body"]))
        changed = copy.copy(current)
        changed.scope = dict(current.scope, view_id="00000000-0000-4000-8000-000000000001")
        with self.assertRaisesRegex(RuntimeError, "scope"):
            unwrap(changed, wrapper, current.node)
        envelope, _ = current.snapshot(2, "b" * 64, "public-canary", "public-demo")
        with self.assertRaisesRegex(RuntimeError, "scope"):
            decrypt_snapshot(changed, envelope, current.read_key)

    def test_exact_candidate_is_not_regenerated_and_incomplete_keys_are_not_replaced(self):
        candidate = self.task / "private" / "candidate.json"
        first = saved_candidate(candidate, lambda: {"expected": {"journal_sequence": "2", "record_hash": "a" * 64}})
        with patch("rotation_cases.write_private", side_effect=AssertionError("must not overwrite")):
            again = saved_candidate(candidate, lambda: (_ for _ in ()).throw(AssertionError("must not regenerate")))
        self.assertEqual(first, again)
        path = self.task / "private" / "incomplete"
        path.mkdir()
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            save_protocol_version(path, self.protocol, "read")
        self.assertEqual(list(path.iterdir()), [])

    def test_version_loader_rejects_replaced_genesis_or_keyset(self):
        path = self.task / "private" / "version"
        save_protocol_version(path, self.protocol, "publisher")
        registration = json.loads((path / "registration.json").read_bytes())
        registration["genesis_hash"] = "f" * 64
        (path / "registration.json").write_bytes(canonical(registration))
        with self.assertRaisesRegex(RuntimeError, "genesis"):
            load_protocol_version(path, self.protocol)

    def test_only_explicit_reviewed_enrollment_revision_can_advance_initial_metadata(self):
        panel = SimpleNamespace(private=self.task / "private")
        reviewed = copy.deepcopy(self.protocol.authority)
        reviewed["revision"] = "3"
        cases = RotationCases(None, panel, self.protocol, lambda *_: None, lambda *_: None,
            reviewed_initial_authority=reviewed)
        self.assertEqual(cases.protocol.authority["revision"], "3")
        self.assertEqual(self.protocol.authority["revision"], "1")
        self.assertIn("[redacted]", repr(cases))
        reviewed["read_key_epoch"] = "2"
        with self.assertRaisesRegex(RuntimeError, "unreviewed"):
            RotationCases(None, panel, self.protocol, lambda *_: None, lambda *_: None,
                reviewed_initial_authority=reviewed)

    def test_rejection_requires_exact_crypto_reason_and_unchanged_canonical_state(self):
        panel = SimpleNamespace(private=self.task / "private")
        cases = RotationCases(None, panel, self.protocol, lambda *_: None, lambda *_: None)
        state = {"cursor": {"journal_sequence": "3", "record_hash": "c" * 64},
            "authority": self.protocol.authority, "snapshot": {"sequence": "1"}}
        with patch.object(cases, "current", return_value=state):
            with self.assertRaisesRegex(RuntimeError, "cryptographic"):
                cases.rejected("fencer", lambda: (403, {"reason": "AuthenticationDenied"}), {"GrantInvalid"})
            self.assertTrue(cases.rejected("fencer", lambda: (400, {"reason": "GrantInvalid"}), {"GrantInvalid"})["rejected"])
        advanced = copy.deepcopy(state)
        advanced["cursor"]["journal_sequence"] = "4"
        with patch.object(cases, "current", side_effect=[state, advanced]):
            with self.assertRaisesRegex(RuntimeError, "advanced"):
                cases.rejected("fencer", lambda: (400, {"reason": "GrantInvalid"}), {"GrantInvalid"})


if __name__ == "__main__":
    unittest.main()
