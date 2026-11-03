"""Real offline CLI seam tests, not mocks and not live Kubernetes evidence.

Set SEKVYR_PROVISION_BIN and its independently measured
SEKVYR_PROVISION_BIN_SHA256 on Linux. No image/VM/network is created here.
All random private keys are created by separate real CLI keygen invocations in
this test's own private directory. Python performs no signing or encryption.
"""

import base64
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

from stage8.provision_adapter import CLIProvider, PinnedCLI, ProvisionError, SecureRoot, canonical, digest, strict

NATIVE_INPUTS = sys.platform == "linux" and os.environ.get("SEKVYR_PROVISION_BIN") and os.environ.get("SEKVYR_PROVISION_BIN_SHA256")
if os.environ.get("CI", "").lower() not in ("", "0", "false") and not NATIVE_INPUTS:
    raise ProvisionError("NativeProvisionCLIRequiredInCI")


def record_hash(record):
    # Test-only expected opaque digest for fixed-schema, integer-only records.
    # Actual signature/semantic/chain validation happens in the real Go CLI.
    return digest(b"sekvyr-e2e2/journal-record-hash/v1\0" + canonical(record))


class NativeFixture:
    def __init__(self, root, binary, sha):
        self.root, self.binary, self.sha = root, binary, sha
        source = root / "fixture"
        source.mkdir(mode=0o700)
        self.files = SecureRoot(source)
        for directory in ("tools", "requests", "outputs"):
            self.files.mkdir(directory)
        self.cli = PinnedCLI(self.files, binary, sha)
        self.public = {}
        for role in ("admin", "publisher", "witness", "fencer", "node", "read"):
            expected = {"read-key.bin"} if role == "read" else {"private.pem", "public.json"}
            self.invoke("keygen", role, {"role": role}, expected)
            if role != "read":
                self.public[role] = strict(self.files.read("outputs/" + role + "/public.json"))
        self.scope = {name + "_id": str(uuid.uuid4()) for name in ("realm", "project", "environment", "view", "log")}
        def key(role):
            return {name: self.public[role][name] for name in ("key_id", "public_key")}
        self.authority = {"revision": "1", "admin_key": key("admin"), "publisher_policy_epoch": "1", "publisher_keys": [key("publisher")],
            "read_key_epoch": "1", "witness_epoch": "1", "witness_key": key("witness"), "fencer_epoch": "1", "fencer_keys": [key("fencer")]}
        self.genesis_body = {"format": "sekvyr-journal-genesis-v1", "scope": self.scope, "panel_origin": "https://panel.example.invalid",
            "authority": self.authority, "recovery_from": None}
        self.files.write("genesis-body", canonical(self.genesis_body))
        self.invoke("genesis", "genesis", {"body_file": "genesis-body", "admin_key_file": "outputs/admin/private.pem", "admin_public_file": "outputs/admin/public.json"},
            {"record.json", "registration.json", "records.json"})
        self.registration = strict(self.files.read("outputs/genesis/registration.json"))
        self.records = strict(self.files.read("outputs/genesis/records.json"))
        self.snapshot = {"sequence": "0", "envelope_hash": "0" * 64, "read_key_epoch": "0", "publisher_policy_epoch": "0"}
        self.enrollments = {}
        self.provider = self.new_provider("provider")
        self.files.write("malformed", b'{"role":"admin","role":"publisher","untrusted":"synthetic-private-canary"}')

    def invoke(self, command, label, request, expected):
        path = "requests/" + label
        self.files.write(path, canonical(request))
        return self.cli.invoke(command, path, "outputs/" + label, expected)

    def new_provider(self, label, registration=None):
        return CLIProvider(self.binary, self.sha, self.root / label, registration=registration or self.registration,
            authority=self.authority, scope=self.scope, panel_origin=self.genesis_body["panel_origin"],
            node_public=base64.urlsafe_b64decode(self.public["node"]["public_key"] + "="), node_fingerprint=self.public["node"]["key_id"],
            key_files={role: self.files.path / "outputs" / role / "private.pem" for role in ("admin", "publisher")},
            read_key=self.files.read("outputs/read/read-key.bin"))

    def cursor(self):
        return {"journal_sequence": self.records[-1]["journal_sequence"], "record_hash": record_hash(self.records[-1])}

    def chain(self, label):
        return self.provider.freeze_chain(label, self.records, self.cursor())

    def append(self, bundle):
        record = bundle.value("record.json")
        self.records.append(record)
        if record["kind"] == "snapshot":
            header = record["envelope"]["body"]["header"]
            self.snapshot = {"sequence": header["sequence"], "envelope_hash": digest(b"sekvyr-e2e2/envelope-hash/v1\0" + bundle.raw("envelope.json")),
                "read_key_epoch": header["read_key_epoch"], "publisher_policy_epoch": header["publisher_policy_epoch"]}
        elif record["kind"] == "transition":
            body = record["transition"]["body"]
            self.authority = body["authority"]
            if body["enrollment"]:
                self.enrollments[body["enrollment"]["installation_id"]] = body["enrollment"]

    def first_snapshot(self):
        bundle = self.provider.snapshot("snapshot-first", self.chain("chain-genesis"), self.snapshot, "public-generation", "public-canary")
        self.append(bundle)
        return bundle

    def installation(self):
        pin = lambda name, key: {"name": name, "uid": str(uuid.uuid4()), "key": key}
        ca = {"name": "ca", "key": "ca.crt"}
        self.config = {"installationID": str(uuid.uuid4()), "namespace": "trial-apps", "serviceAccount": "operator", "serviceAccountUID": str(uuid.uuid4()),
            "leaderElectionLeaseName": "leader", "leaderElectionLeaseUID": str(uuid.uuid4()), "bootstrapGeneration": 1,
            "allowedPanelOrigins": ["https://panel.example.invalid"], "allowedWitnessOrigins": ["https://witness.example.invalid"],
            "identityKeySecret": pin("node", "node.pem"), "trustBundleSecret": pin("trust", "trust.json"), "stateSecret": pin("state", "installation.json"),
            "protectedSecretNames": [], "protectedSecretUIDs": [], "protectedPrefixes": [], "allowedTargetSecrets": ["target"],
            "caConfigMaps": [{**ca, "uid": str(uuid.uuid4()), "derSetSHA256": "a" * 64}],
            "ha": {"trial": True, "fencerOrigin": "https://fencer.example.invalid", "allowedFencerOrigins": ["https://fencer.example.invalid"],
                "fencerCAConfigMapRef": ca, "gatewayOrigin": "https://gateway.example.invalid", "gatewayCAConfigMapRef": ca,
                "gatewayClientSecret": pin("gateway-client", "tls.crt"), "gatewayClientKeyKey": "tls.key", "journal": self.registration}}
        c = self.config
        self.binding = {"id": str(uuid.uuid4()), "name": "app", "resourceName": "app-secret", "source": {"group": "", "project": "demo", "environment": "prod", "pathPrefix": "/", "viewId": self.scope["view_id"]},
            "selection": {"mode": "All"}, "encryption": {"mode": "E2E", "protocol": "e2e2", "trustKey": "view", "freshness": {"mode": "WitnessCurrent"}},
            "target": {"name": "target"}, "rollout": {"allowedDeployments": []}}
        target_uid = str(uuid.uuid4())
        self.receipts = {"enrollment": {"installation_id": c["installationID"], "bootstrap_generation": 1, "namespace": c["namespace"], "namespace_uid": str(uuid.uuid4()),
            "operator_service_account": c["serviceAccount"], "operator_service_account_uid": c["serviceAccountUID"],
            "fencer_service_account": "fencer", "fencer_service_account_uid": str(uuid.uuid4()),
            "lease": {"api_version": "coordination.k8s.io/v1", "kind": "Lease", "namespace": c["namespace"], "name": "leader", "uid": c["leaderElectionLeaseUID"]},
            "node_fingerprint": self.public["node"]["key_id"], "identity_key_secret_uid": c["identityKeySecret"]["uid"], "trust_bundle_secret_uid": c["trustBundleSecret"]["uid"],
            "allowed_objects": [{"api_version": "v1", "kind": "Secret", "namespace": c["namespace"], "name": "state", "uid": c["stateSecret"]["uid"]},
                {"api_version": "v1", "kind": "Secret", "namespace": c["namespace"], "name": "target", "uid": target_uid}]},
            "binding": {"store_name": "store", "store_uid": str(uuid.uuid4()), "cr_name": "app-secret", "cr_uid": str(uuid.uuid4()), "binding_id": self.binding["id"],
                "view_id": self.scope["view_id"], "target_name": "target", "target_uid": target_uid, "cr_generation": 1, "store_generation": 1, "identity": ""}}

    def enroll(self, label):
        authority = copy.deepcopy(self.authority)
        authority["revision"] = str(int(authority["revision"]) + 1)
        # Test-only opaque expected digest; the actual CLI replays all prior
        # records and rejects it unless it equals the real Go authority digest.
        previous = digest(b"sekvyr-e2e2/authority-state-hash/v1\0" + canonical({"scope": self.scope,
            "genesis_hash": self.registration["genesis_hash"], "authority": self.authority, "enrollments": self.enrollments}))
        body = {"format": "sekvyr-authority-transition-v1", "scope": self.scope, "genesis_hash": self.registration["genesis_hash"], "expected": self.cursor(),
            "previous_authority_digest": previous, "kind": "enroll-installation", "authority": authority,
            "enrollment": self.receipts["enrollment"], "activating_envelope": None, "recovery_from": None}
        bundle = self.provider.transition(label, self.chain(label + "-chain"), body)
        self.append(bundle)

    def recovery_body(self, operation="initialize", previous_uid="", raw=b""):
        c = self.config
        return {"format": "sekvyr-checkpoint-recovery-v1", "operation": operation, "recovery_id": str(uuid.uuid4()), "installation_id": c["installationID"],
            "previous_bootstrap_generation": 0 if operation == "initialize" else 1, "previous_state_secret_uid": previous_uid,
            "bootstrap_generation": c["bootstrapGeneration"], "state_secret_name": c["stateSecret"]["name"], "state_secret_uid": c["stateSecret"]["uid"],
            "identity_key_secret_uid": c["identityKeySecret"]["uid"], "trust_bundle_secret_uid": c["trustBundleSecret"]["uid"], "node_fingerprint": self.public["node"]["key_id"],
            "scope": self.scope, "genesis_hash": self.registration["genesis_hash"], "cursor": self.cursor(), "snapshot": self.snapshot, "binding": self.receipts["binding"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expected_state_sha256": digest(raw), "allow_rollout": False}

    def close(self):
        self.provider.close()
        self.files.close()


@unittest.skipUnless(NATIVE_INPUTS,
    "Explicit independently hash-pinned Linux CLI required; no substitute/fake binary")
class NativeCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = NativeFixture(Path(self.temp.name), Path(os.environ["SEKVYR_PROVISION_BIN"]), os.environ["SEKVYR_PROVISION_BIN_SHA256"])
        self.addCleanup(self.f.close)

    def test_real_cli_genesis_snapshot_wrap_bootstrap_enrollment_and_recovery(self):
        f = self.f
        genesis = f.provider.genesis("genesis-equivalence", f.genesis_body)
        self.assertEqual(genesis.value("records.json"), f.records)
        first = f.first_snapshot()
        self.assertNotIn("private", str(first.value("candidate.json")))
        f.installation()
        # Real Kubernetes bindings can contain the explicit CRD default.
        f.binding["target"]["allowEmpty"] = False
        boot = f.provider.bootstrap("bootstrap", f.chain("bootstrap-chain"), f.config, f.receipts, f.binding)
        self.assertIs(f.binding["target"]["allowEmpty"], False)
        f.receipts = boot.value("receipts.json")
        self.assertTrue(f.receipts["binding"]["identity"])
        self.assertEqual(boot.value("installation.json"), f.config)
        f.enroll("enroll")
        body = f.recovery_body()
        plan = f.provider.recovery("initialize", f.chain("initialize-chain"), f.config, f.receipts, f.binding, body)
        self.assertEqual(plan.value("plan.json")["body"], body)
        original = first.raw("envelope.json")
        with self.assertRaises(ProvisionError):
            f.provider.snapshot("snapshot-first", f.chain("no-new-nonce"), f.snapshot, "another", "another")
        self.assertEqual(first.raw("envelope.json"), original)

    def test_actual_cli_rejects_malformed_and_wrong_role(self):
        f = self.f
        with self.assertRaises(ProvisionError) as error:
            f.cli.invoke("keygen", "malformed", "outputs/malformed", {"private.pem", "public.json"})
        self.assertNotIn("synthetic-private-canary", str(error.exception))
        f.provider.key_files["publisher"] = f.files.path / "outputs/witness/private.pem"
        with self.assertRaises(ProvisionError):
            f.provider.snapshot("wrong-role", f.chain("wrong-role-chain"), f.snapshot, "public", "public")

    def test_actual_cli_rejects_prefix_below_independent_floor(self):
        f = self.f
        registration = copy.deepcopy(f.registration)
        registration["minimum_cursor"] = {"journal_sequence": "1", "record_hash": "a" * 64}
        other = f.new_provider("floor-pinned-provider", registration)
        self.addCleanup(other.close)
        chain = other.freeze_chain("incomplete-prefix", f.records, f.cursor())
        with self.assertRaises(ProvisionError): other.snapshot("below-floor", chain, f.snapshot, "public", "public")

    def test_actual_cli_wrong_uid_and_exact_recovery_state_bytes(self):
        f = self.f
        f.first_snapshot(); f.installation()
        bad = copy.deepcopy(f.receipts); bad["enrollment"]["identity_key_secret_uid"] = str(uuid.uuid4())
        with self.assertRaises(ProvisionError): f.provider.bootstrap("wrong-uid", f.chain("wrong-uid-chain"), f.config, bad, f.binding)
        boot = f.provider.bootstrap("bootstrap", f.chain("bootstrap-chain"), f.config, f.receipts, f.binding)
        f.receipts = boot.value("receipts.json"); f.enroll("enroll")
        old_uid = f.config["stateSecret"]["uid"]
        f.config["bootstrapGeneration"] = 2
        f.config["stateSecret"].update(name="state-gen2", uid=str(uuid.uuid4()))
        f.config["trustBundleSecret"].update(name="trust-gen2", uid=str(uuid.uuid4()))
        f.receipts["enrollment"].update(bootstrap_generation=2, trust_bundle_secret_uid=f.config["trustBundleSecret"]["uid"])
        f.receipts["enrollment"]["allowed_objects"][0].update(name="state-gen2", uid=f.config["stateSecret"]["uid"])
        f.enroll("enroll-gen2")
        raw = b'{"public_synthetic":"exact retained state bytes"}\n'
        body = f.recovery_body("recover", old_uid, raw)
        plan = f.provider.recovery("recover", f.chain("recover-chain"), f.config, f.receipts, f.binding, body, raw)
        self.assertEqual(plan.value("plan.json")["body"]["expected_state_sha256"], digest(raw))
        with self.assertRaises(ProvisionError):
            f.provider.recovery("changed-state", f.chain("changed-state-chain"), f.config, f.receipts, f.binding, body, raw + b" ")


if __name__ == "__main__":
    unittest.main()
