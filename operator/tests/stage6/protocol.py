"""Offline admin/publisher fixture for the actual Go journal protocol.

These are ephemeral test signing keys, never gateway or witness read keys.
Runtime validation remains in Go; this module only constructs test inputs.
"""

import hashlib
import copy
import json
import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from fixture import canonical, pem, safe_task, token, write_private


def b64(raw):
    import base64
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def domain(name):
    return name.encode("ascii") + b"\0"


def key_descriptor(private):
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"key_id": "ed25519-sha256:" + hashlib.sha256(public).hexdigest(), "public_key": b64(public)}


def signed(name, value, key):
    return {"body": value, "key_id": key_descriptor(key)["key_id"],
            "signature": b64(key.sign(domain(name) + canonical(value)))}


def record_hash(record):
    return hashlib.sha256(domain("sekvyr-e2e2/journal-record-hash/v1") + canonical(record)).hexdigest()


def record(log_id, sequence, previous_hash, kind, payload):
    fields = {"genesis": None, "envelope": None, "transition": None, "fence_grant": None, "fence_activation": None}
    field = {"genesis": "genesis", "snapshot": "envelope", "transition": "transition",
             "fence-grant": "fence_grant", "fence-activation": "fence_activation"}.get(kind)
    if field is None:
        raise ValueError("Unknown trial record kind")
    fields[field] = payload
    return {"format": "sekvyr-journal-record-v1", "log_id": log_id, "journal_sequence": str(sequence),
            "previous_record_hash": previous_hash, "kind": kind, **fields}


class ProtocolAuthority:
    def __init__(self, task):
        task = safe_task(task)
        self.root = task / "private" / "protocol"
        self.root.mkdir(mode=0o700)
        fixture = json.loads((task / "private" / "fixture.json").read_text(encoding="utf-8"))
        self.scope = {name + "_id": str(uuid.uuid4()) for name in ("realm", "project", "environment", "view", "log")}
        self.installation_id, self.binding_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.admin, self.publisher, self.witness, self.fencer = [ed25519.Ed25519PrivateKey.generate() for _ in range(4)]
        self.node = ec.generate_private_key(ec.SECP256R1())
        self.read_key = os.urandom(32)
        self.panel_origin = "https://panel." + fixture["namespaces"]["panel"] + ".svc.cluster.local:8443"
        self.authority = {"revision": "1", "admin_key": key_descriptor(self.admin),
            "publisher_policy_epoch": "1", "publisher_keys": [key_descriptor(self.publisher)], "read_key_epoch": "1",
            "witness_epoch": "1", "witness_key": key_descriptor(self.witness),
            "fencer_epoch": "1", "fencer_keys": [key_descriptor(self.fencer)]}
        for label in ("admin", "publisher", "witness", "fencer", "node"):
            write_private(self.root / (label + ".key"), pem(getattr(self, label)))
        write_private(self.root / "context.json", canonical({"scope": self.scope, "installation_id": self.installation_id,
            "binding_id": self.binding_id, "read_key": b64(self.read_key), "panel_origin": self.panel_origin,
            "authority": self.authority}))
        genesis = signed("sekvyr-e2e2/journal-genesis/v1", {"format": "sekvyr-journal-genesis-v1", "scope": self.scope,
            "panel_origin": self.panel_origin, "authority": self.authority, "recovery_from": None}, self.admin)
        self.genesis_record = record(self.scope["log_id"], 0, "0" * 64, "genesis", genesis)
        self.genesis_hash = record_hash(self.genesis_record)
        self.registration = {"log_id": self.scope["log_id"], "genesis_hash": self.genesis_hash,
            "admin_public_key": key_descriptor(self.admin)["public_key"],
            "minimum_cursor": {"journal_sequence": "0", "record_hash": self.genesis_hash}}
        write_private(self.root / "genesis-record.json", canonical(self.genesis_record))
        write_private(self.root / "registration.json", canonical(self.registration))
        self.prepare_fault_logs()

    def prepare_fault_logs(self):
        """Explicitly create NEW diagnostic logs; never reset the primary log."""
        self.fault_logs = {}
        for label in ("duplicate-version", "delete-marker", "replica-cas"):
            scope = dict(self.scope, log_id=str(uuid.uuid4()))
            genesis = signed("sekvyr-e2e2/journal-genesis/v1", {"format": "sekvyr-journal-genesis-v1", "scope": scope,
                "panel_origin": self.panel_origin, "authority": self.authority, "recovery_from": None}, self.admin)
            raw_record = record(scope["log_id"], 0, "0" * 64, "genesis", genesis)
            digest = record_hash(raw_record)
            self.fault_logs[label] = {"record": raw_record, "registration": {"log_id": scope["log_id"],
                "genesis_hash": digest, "admin_public_key": key_descriptor(self.admin)["public_key"],
                "minimum_cursor": {"journal_sequence": "0", "record_hash": digest}}}
        write_private(self.root / "fault-logs.json", canonical(self.fault_logs))

    def prepare_replica_cas_log(self):
        if "replica-cas" in self.fault_logs:
            raise ValueError("Replica CAS fixture already exists")
        scope = dict(self.scope, log_id=str(uuid.uuid4()))
        genesis = signed("sekvyr-e2e2/journal-genesis/v1", {"format": "sekvyr-journal-genesis-v1", "scope": scope,
            "panel_origin": self.panel_origin, "authority": self.authority, "recovery_from": None}, self.admin)
        raw = record(scope["log_id"], 0, "0" * 64, "genesis", genesis)
        digest = record_hash(raw)
        value = {"record": raw, "registration": {"log_id": scope["log_id"], "genesis_hash": digest,
            "admin_public_key": key_descriptor(self.admin)["public_key"],
            "minimum_cursor": {"journal_sequence": "0", "record_hash": digest}}}
        write_private(self.root / "replica-cas.json", canonical(value))
        self.fault_logs["replica-cas"] = value

    def __repr__(self):
        return "<offline stage6 protocol authority [redacted]>"

    @property
    def node_public(self):
        return self.node.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    @property
    def node_fingerprint(self):
        return "p256-sha256:" + hashlib.sha256(self.node_public).hexdigest()

    def snapshot(self, sequence, previous_hash, generation, demo_value, action=None, restored_from=None):
        entries = [{"path": "/runtime", "name": "DEMO_VALUE", "value": demo_value},
                   {"path": "/runtime", "name": "GENERATION", "value": generation}]
        header = {"protocol": "e2e2", "suite": "HKDF-SHA256+A256GCM+Ed25519", "intent": "publish", **self.scope,
            "sequence": str(sequence), "previous_hash": previous_hash, "read_key_epoch": self.authority["read_key_epoch"],
            "publisher_policy_epoch": self.authority["publisher_policy_epoch"], "publisher_key_id": key_descriptor(self.publisher)["key_id"],
            "snapshot_salt": b64(os.urandom(32)), "entry_count": len(entries),
            "action": action or ("initial" if sequence == 1 else "update"), "restored_from": restored_from, "parents": []}
        import base64
        salt = base64.urlsafe_b64decode(header["snapshot_salt"] + "=")
        nonce = os.urandom(12)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
            info=domain("sekvyr-e2e2/snapshot-key/v1") + canonical(header)).derive(self.read_key)
        values = {"format": "sekvyr-e2e2-values-v1", "context": self.scope, "entries": entries}
        ciphertext = AESGCM(key).encrypt(nonce, canonical(values), domain("sekvyr-e2e2/snapshot-aad/v1") + canonical(header))
        body = {"header": header, "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        envelope = {"body": body, "signature": b64(self.publisher.sign(domain("sekvyr-e2e2/publish/v1") + canonical(body)))}
        digest = hashlib.sha256(domain("sekvyr-e2e2/envelope-hash/v1") + canonical(envelope)).hexdigest()
        return envelope, digest

    def reader_wrap(self):
        context = {"protocol": "e2e2-reader-key-v1", **self.scope, "read_key_epoch": self.authority["read_key_epoch"],
            "publisher_policy_epoch": self.authority["publisher_policy_epoch"], "publisher_key_id": key_descriptor(self.publisher)["key_id"],
            "recipient_fingerprint": self.node_fingerprint}
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        shared = ephemeral.exchange(ec.ECDH(), self.node.public_key())
        salt, nonce = os.urandom(32), os.urandom(12)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
            info=domain("sekvyr-e2e2/reader-wrap-key/v1") + canonical(context)).derive(shared)
        payload = {"format": "sekvyr-e2e2-read-key-v1", "context": context, "read_key": b64(self.read_key)}
        ciphertext = AESGCM(key).encrypt(nonce, canonical(payload), domain("sekvyr-e2e2/reader-wrap-aad/v1") + canonical(context))
        body = {"context": context, "ephemeral_public": b64(ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)), "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        return {"body": body, "signature": b64(self.publisher.sign(domain("sekvyr-e2e2/reader-wrap-sign/v1") + canonical(body)))}

    def transition(self, kind, current, authority=None, enrollment=None, activating_envelope=None, recovery_from=None):
        if authority is None:
            authority = copy.deepcopy(current["authority"])
            authority["revision"] = str(int(authority["revision"]) + 1)
        body = {"format": "sekvyr-authority-transition-v1", "scope": self.scope, "genesis_hash": self.genesis_hash,
            "expected": current["cursor"], "previous_authority_digest": current["authority_digest"], "kind": kind,
            "authority": authority, "enrollment": enrollment,
            "activating_envelope": activating_envelope, "recovery_from": recovery_from}
        return signed("sekvyr-e2e2/authority-transition/v1", body, self.admin)

    @classmethod
    def load(cls, task):
        task = safe_task(task)
        value = cls.__new__(cls)
        value.root = task / "private" / "protocol"
        context = json.loads((value.root / "context.json").read_text(encoding="utf-8"))
        for key, item in context.items():
            setattr(value, key, item)
        for label in ("admin", "publisher", "witness", "fencer", "node"):
            setattr(value, label, serialization.load_pem_private_key((value.root / (label + ".key")).read_bytes(), password=None))
        import base64
        value.read_key = base64.urlsafe_b64decode(value.read_key + "=")
        value.genesis_record = json.loads((value.root / "genesis-record.json").read_text(encoding="utf-8"))
        value.registration = json.loads((value.root / "registration.json").read_text(encoding="utf-8"))
        faults = value.root / "fault-logs.json"
        value.fault_logs = json.loads(faults.read_text(encoding="utf-8")) if faults.exists() else {}
        extra = value.root / "replica-cas.json"
        if extra.exists():
            if "replica-cas" in value.fault_logs:
                raise ValueError("Duplicate replica CAS fixture")
            value.fault_logs["replica-cas"] = json.loads(extra.read_text(encoding="utf-8"))
        value.genesis_hash = record_hash(value.genesis_record)
        if value.genesis_hash != value.registration["genesis_hash"]:
            raise ValueError("Offline fixture genesis mismatch")
        return value


def gateway_config(task, protocol):
    """No keys in config; AWS credentials are mounted only in gateway process."""
    task = safe_task(task)
    fixture = json.loads((task / "private" / "fixture.json").read_text(encoding="utf-8"))
    storage = fixture["namespaces"]["storage"]
    roles = {"admin": ["genesis", "transition"], "witness-a": ["snapshot", "transition"],
             "witness-b": ["snapshot", "transition"], "fencer": ["fence-grant", "fence-activation"], "operator": []}
    registrations = [protocol.registration] + [entry["registration"] for entry in protocol.fault_logs.values()]
    replica_log = protocol.fault_logs.get("replica-cas", {}).get("registration", {}).get("log_id")
    return {"format": "sekvyr-journal-gateway-config-v1", "s3": {
        "bucket": fixture["bucket"], "prefix": "canonical/", "region": "us-east-1",
        "endpoint": "https://s3." + storage + ".svc.cluster.local:8333", "ca_file": "/trust/storage-ca.crt",
        "expected_bucket_owner": "", "retain_seconds": 86400, "allow_http_trial": False},
        "registrations": registrations, "clients": [{"common_name": "isolated-trial-" + role,
            "logs": ([entry["log_id"] for entry in registrations] if role == "admin" else
                     [protocol.scope["log_id"], replica_log] if role in ("witness-a", "witness-b") and replica_log else [protocol.scope["log_id"]]),
            "write_kinds": kinds} for role, kinds in roles.items()]}
