"""Explicit CLI artifact -> existing owner APIs/native recovery bridge.

Only parent/coordinator calls these methods in its approved live trial. No
network call, cluster mutation, VM or process is started on module import.
"""

import base64
import copy
from datetime import datetime, timedelta, timezone
import uuid

from application import RESOURCE, STORE, TARGET
from stage8.provision_adapter import canonical, counter, digest, read_external, require, safe_public, strict


def complete_chain_reader(gateway_client, log_id, read_bookend):
    """Bind existing mTLS client/framing to a bounded, explicit record source.

    This does not authenticate signatures or claim physical retention: every
    receiving CLI command replays original pins, and online runtime gates stay.
    """
    require(callable(read_bookend), "CLIExplicitTransportsRequired")
    @safe_public
    def read():
        bookend = read_bookend()
        require(bookend["scope"]["log_id"] == log_id, "CLIJournalScopeChanged")
        expected = bookend["cursor"]
        nonce, (status, raw, _) = gateway_client.journal(log_id)
        require(status == 200 and type(raw) is bytes and len(raw) <= 64 << 20, "CLIJournalBoundsRejected")
        lines = raw.splitlines()
        require(3 <= len(lines) <= 4098, "CLIJournalBoundsRejected")
        begin, end = strict(lines[0], 4096), strict(lines[-1], 4096)
        fields = {"format", "nonce", "count", "last_record_hash"}
        require(set(begin) == fields and set(end) == fields and type(begin["count"]) is int
            and type(end["count"]) is int and 1 <= begin["count"] <= 4096 and begin["count"] == end["count"] == len(lines) - 2
            and begin["format"] == "sekvyr-journal-stream-begin-v1" and end["format"] == "sekvyr-journal-stream-end-v1"
            and begin["nonce"] == end["nonce"] == nonce
            and begin["last_record_hash"] == end["last_record_hash"] == expected["record_hash"], "CLIJournalFramingRejected")
        records = []
        for index, line in enumerate(lines[1:-1]):
            slot = strict(line, (16 << 20) + (256 << 10))
            require(set(slot) == {"sequence", "receipt", "record"} and slot["sequence"] == str(index)
                and slot["record"]["journal_sequence"] == str(index) and slot["record"]["log_id"] == log_id,
                "CLIJournalOrderRejected")
            records.append(slot["record"])
        require(expected["journal_sequence"] == str(len(records) - 1), "CLIJournalCursorChanged")
        return records, copy.deepcopy(expected)
    return read


class LiveCLIProvider:
    def __init__(self, coordinator, provider, read_complete_chain, recover):
        require(callable(read_complete_chain) and callable(recover), "CLIExplicitTransportsRequired")
        require(coordinator.protocol.scope == provider.scope and coordinator.protocol.registration == provider.registration,
            "CLIIndependentPinsDiffer")
        self.c, self.provider = coordinator, provider
        self.read_complete_chain, self.native_recover = read_complete_chain, recover
        self.snapshots = {}
        self.bootstrap_bundle = None

    def __repr__(self):
        return "<explicit live CLI artifact bridge [redacted]>"

    @safe_public
    def current(self):
        value = self.c.current()
        require(value["scope"] == self.provider.scope and value["genesis_hash"] == self.provider.registration["genesis_hash"], "CLICurrentBookendMismatch")
        # Incoming keys never become pins: known offline roles/epochs must match.
        known, incoming = copy.deepcopy(self.provider.authority), copy.deepcopy(value["authority"])
        known.pop("revision"); incoming.pop("revision")
        require(known == incoming, "CLIUnreviewedAuthorityChange")
        require(counter(value["authority"]["revision"]) > 0, "CLICurrentBookendMismatch")
        counter(value["cursor"]["journal_sequence"])
        counter(value["snapshot"]["sequence"])
        return value

    @safe_public
    def chain(self, label, current):
        # read_complete_chain returns the bounded full signed record array and
        # explicit expected cursor, from the coordinator's mTLS journal stream.
        # The Go command authenticates it against original independent pins.
        records, cursor = self.read_complete_chain()
        require(cursor == current["cursor"], "CLIJournalChangedBeforePreparation")
        return self.provider.freeze_chain(label, records, cursor)

    @safe_public
    def prepare_snapshot(self, label, generation, demo):
        current = self.current()
        chain = self.chain(label + "-before", current)
        bundle = self.provider.snapshot(label, chain, current["snapshot"], generation, demo)
        envelope = bundle.raw("envelope.json")
        envelope_hash = digest(b"sekvyr-e2e2/envelope-hash/v1\0" + envelope)
        record = bundle.value("record.json")
        require(record["previous_record_hash"] == chain["expected_cursor"]["record_hash"]
            and record["envelope"] == strict(envelope), "CLICandidateContextChanged")
        self.snapshots[envelope_hash] = bundle
        return bundle, {"sequence": record["envelope"]["body"]["header"]["sequence"], "envelope_hash": envelope_hash}, current["cursor"]

    @safe_public
    def commit_snapshot(self, bundle, snapshot, expected_cursor):
        record = bundle.value("record.json")
        n = counter(record["journal_sequence"])
        require(n > 0 and expected_cursor == {"journal_sequence": str(n - 1),
            "record_hash": record["previous_record_hash"]}, "CLICandidateCannotRebase")
        require(self.current()["cursor"] == expected_cursor, "CLIJournalChangedBeforeCommit")
        require(bundle.value("candidate.json") == {"pending": False, "committed": False}, "CLIPendingCannotCommit")
        envelope = bundle.value("envelope.json")
        require(digest(b"sekvyr-e2e2/envelope-hash/v1\0" + bundle.raw("envelope.json")) == snapshot["envelope_hash"], "CLISnapshotDigestChanged")
        view = self.provider.scope["view_id"]
        _, staged = self.c.panel.owner_request("POST", "/api/e2e2/views/" + view + "/envelopes", envelope, (201,))
        require(staged["envelope_hash"] == snapshot["envelope_hash"], "CLIStagedHashChanged")
        # Exact saved expected cursor, never a freshly learned CAS base.
        self.c.panel.witness_client.request("POST", "/v2/logs/" + self.provider.scope["log_id"] + "/commits",
            canonical({"expected": expected_cursor, "envelope_hash": snapshot["envelope_hash"]}), {"Content-Type": "application/json"})
        _, projected = self.c.panel.owner_request("POST", "/api/e2e2/views/" + view + "/rotation-project", {})
        require(projected["envelope_hash"] == snapshot["envelope_hash"] and self.current()["snapshot"] == {
            **snapshot, "read_key_epoch": envelope["body"]["header"]["read_key_epoch"],
            "publisher_policy_epoch": envelope["body"]["header"]["publisher_policy_epoch"]}, "CLICanonicalSnapshotChanged")
        return snapshot

    @safe_public
    def grant_reader(self, bundle):
        meta = strict(read_external(self.c.private / "panel-bootstrap.json", 16 << 10), 16 << 10)
        _, result = self.c.panel.owner_request("POST", "/api/e2e2/views/" + self.provider.scope["view_id"] + "/readers",
            {"machine_id": meta["machine_id"], "wrapper": bundle.value("reader-wrap.json")})
        require(result.get("has_wrap") is True, "CLIReaderWrapNotGranted")

    @safe_public
    def publish(self, generation, demo, *, label):
        bundle, snapshot, expected = self.prepare_snapshot(label, generation, demo)
        self.commit_snapshot(bundle, snapshot, expected)
        self.grant_reader(bundle)
        # Pending rollout verification needs the whole checkpoint. Use the
        # saved CLI envelope whose exact metadata was checked at commit.
        header = bundle.value("envelope.json")["body"]["header"]
        return {**snapshot, "read_key_epoch": header["read_key_epoch"],
            "publisher_policy_epoch": header["publisher_policy_epoch"]}

    @safe_public
    def uid_receipts(self, identity=""):
        app = self.c.app
        cr, store, target = app.get("SekvyrSecret", RESOURCE), app.get("SekvyrStore", STORE), app.get("Secret", TARGET)
        require(store["spec"]["bindings"] == [app.binding], "CLIBindingChanged")
        return {"enrollment": app.enrollment(), "binding": {"store_name": STORE, "store_uid": store["metadata"]["uid"],
            "cr_name": RESOURCE, "cr_uid": cr["metadata"]["uid"], "binding_id": app.binding["id"], "view_id": self.provider.scope["view_id"],
            "target_name": TARGET, "target_uid": target["metadata"]["uid"], "cr_generation": cr["metadata"]["generation"],
            "store_generation": store["metadata"]["generation"], "identity": identity}}

    @safe_public
    def bootstrap(self, label, installation):
        require(self.bootstrap_bundle is None, "CLIBootstrapAlreadyPrepared")
        current = self.current()
        require(current["snapshot"]["sequence"] != "0", "CLIPositiveCanonicalFloorRequired")
        chain = self.chain(label + "-before", current)
        bundle = self.provider.bootstrap(label, chain, installation, self.uid_receipts(), self.c.app.binding)
        self.c.app.populate_cli_trust(bundle, installation)
        self.bootstrap_bundle = bundle
        return {"cliBootstrapConsumed": True, "trustImmutableBeforeRuntime": True, "production": False}

    @safe_public
    def enroll(self, label):
        require(self.bootstrap_bundle is not None and self.c.app.cli_trust_complete, "CLITrustNotComplete")
        current = self.current()
        chain = self.chain(label + "-before", current)
        authority = copy.deepcopy(self.provider.authority)
        authority["revision"] = str(int(current["authority"]["revision"]) + 1)
        body = {"format": "sekvyr-authority-transition-v1", "scope": self.provider.scope,
            "genesis_hash": self.provider.registration["genesis_hash"], "expected": chain["expected_cursor"],
            "previous_authority_digest": current["authority_digest"], "kind": "enroll-installation", "authority": authority,
            "enrollment": self.c.app.enrollment(), "activating_envelope": None, "recovery_from": None}
        bundle = self.provider.transition(label, chain, body)
        require(self.current()["cursor"] == chain["expected_cursor"], "CLIJournalChangedBeforeCommit")
        self.c.panel.witness_client.request("POST", "/v2/logs/" + self.provider.scope["log_id"] + "/transitions",
            bundle.raw("transition.json"), {"Content-Type": "application/json"})
        require(self.current()["enrollments"].get(self.c.protocol.installation_id) == body["enrollment"], "CLIEnrollmentNotCanonical")
        return {"cliSignedEnrollmentCommitted": True, "production": False}

    @safe_public
    def initialize(self, label, installation):
        require(self.bootstrap_bundle is not None and self.c.app.cli_trust_complete, "CLITrustNotComplete")
        current = self.current()
        chain = self.chain(label + "-before", current)
        normalized = self.bootstrap_bundle.value("receipts.json")
        actual = self.uid_receipts(normalized["binding"]["identity"])
        require(actual == normalized and installation == self.bootstrap_bundle.value("installation.json"), "CLIUIDReceiptChanged")
        app = self.c.app
        state = app.get("Secret", app.state_name)
        raw = base64.b64decode(state.get("data", {}).get("state.json", ""), validate=True)
        require(raw == b"" and app.generation == 1, "CLIInitializeCannotResetState")
        require(current["snapshot"]["envelope_hash"] in self.snapshots, "CLIUnknownSnapshotExport")
        snapshot_bundle = self.snapshots[current["snapshot"]["envelope_hash"]]
        body = {"format": "sekvyr-checkpoint-recovery-v1", "operation": "initialize", "recovery_id": str(uuid.uuid4()),
            "installation_id": app.protocol.installation_id, "previous_bootstrap_generation": 0, "previous_state_secret_uid": "",
            "bootstrap_generation": 1, "state_secret_name": app.state_name, "state_secret_uid": state["metadata"]["uid"],
            "identity_key_secret_uid": installation["identityKeySecret"]["uid"], "trust_bundle_secret_uid": installation["trustBundleSecret"]["uid"],
            "node_fingerprint": self.provider.node_fingerprint, "scope": self.provider.scope,
            "genesis_hash": self.provider.registration["genesis_hash"], "cursor": chain["expected_cursor"], "snapshot": current["snapshot"],
            "binding": normalized["binding"], "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expected_state_sha256": digest(raw), "allow_rollout": False}
        plan = self.provider.recovery(label, chain, installation, normalized, app.binding, body)
        require(self.current()["cursor"] == chain["expected_cursor"], "CLIJournalChangedBeforeRecovery")
        result = self.native_recover(plan.value("plan.json"), snapshot_bundle.raw("envelope.json"), snapshot_bundle.raw("reader-wrap.json"), installation)
        require(type(result) is dict and result.get("checkpointRecoveryComplete") is True, "CLINativeRecoveryNotComplete")
        app.start_application_after_initialize()
        return {"cliSignedInitializeConsumedByNativeRecovery": True, "production": False}
