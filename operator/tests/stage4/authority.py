"""Ephemeral test publisher and TLS roots, generated outside the source tree."""

import base64
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def domain(name):
    return ("sekvyr-e2e2/" + name + "/v1").encode("ascii") + b"\0"


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(key):
    return "ed25519-sha256:" + hashlib.sha256(public(key)).hexdigest()


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def protected_write(path, content):
    raw = content.encode() if isinstance(content, str) else content
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def ca_pin(certificate_pem):
    cert = x509.load_pem_x509_certificate(certificate_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(len(der).to_bytes(4, "big") + der).hexdigest()


def make_tls(root, label, hostnames):
    now = datetime.now(timezone.utc)
    ca = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-stage4-" + label + "-ca")])
    ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(ca.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                           key_encipherment=False, data_encipherment=False,
                                           key_agreement=False, key_cert_sign=True, crl_sign=True,
                                           encipher_only=False, decipher_only=False), critical=True)
               .sign(ca, hashes.SHA256()))
    server = ec.generate_private_key(ec.SECP256R1())
    # SAN carries the exact service DNS names. Keep CN below its 64-byte limit
    # even when a unique remote namespace makes the full witness DNS longer.
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-stage4-" + label)])
    server_cert = (x509.CertificateBuilder().subject_name(server_name).issuer_name(name)
                   .public_key(server.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in hostnames]), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(ca, hashes.SHA256()))
    cert = ca_cert.public_bytes(serialization.Encoding.PEM)
    protected_write(root / (label + "-ca.crt"), cert)
    protected_write(root / (label + "-tls.crt"), server_cert.public_bytes(serialization.Encoding.PEM))
    protected_write(root / (label + "-tls.key"), pem(server))
    return cert


class Authority:
    @staticmethod
    def safe_task(task_dir):
        task_dir = Path(task_dir).resolve()
        local = task_dir.parent == Path("/tmp") and re.fullmatch(r"sekvyr-stage[45]\.[A-Za-z0-9]+", task_dir.name)
        server = task_dir.parent == Path("/opt/sekvyr-trial") and re.fullmatch(r"sekvyr-stage[45]-[0-9]{8}-[0-9a-f]{8}", task_dir.name)
        if not (local or server):
            raise ValueError("Unexpected private task directory")
        return task_dir

    def __init__(self, task_dir, panel_namespace="stage4-panel", witness_namespace="stage4-witness"):
        task_dir = self.safe_task(task_dir)
        self.root = task_dir / "private"
        self.root.mkdir(mode=0o700)
        self.scope = {name + "_id": str(uuid.uuid4()) for name in ("realm", "project", "environment", "view", "log")}
        self.installation_id = str(uuid.uuid4())
        self.binding_id = str(uuid.uuid4())
        self.publisher = ed25519.Ed25519PrivateKey.generate()
        self.witness = ed25519.Ed25519PrivateKey.generate()
        self.admin = ed25519.Ed25519PrivateKey.generate()
        self.node = ec.generate_private_key(ec.SECP256R1())
        self.read_key = os.urandom(32)
        self.fetch_token = b64(os.urandom(48))
        self.owner_password = "test-password-" + b64(os.urandom(24))
        self.db_password = b64(os.urandom(24))
        self.jwt_secret = b64(os.urandom(48))
        self.root_key = base64.b64encode(os.urandom(32)).decode()
        panel_host = "panel." + panel_namespace + ".svc.cluster.local"
        witness_host = "witness." + witness_namespace + ".svc.cluster.local"
        self.panel_origin = "https://" + panel_host + ":8443"
        self.witness_origin = "https://" + witness_host + ":8443"
        self.panel_ca = make_tls(self.root, "panel", [panel_host, "panel." + panel_namespace + ".svc", "localhost"])
        self.witness_ca = make_tls(self.root, "witness", [witness_host, "witness." + witness_namespace + ".svc", "localhost"])
        for name, data in {
            "publisher.pkcs8.pem": pem(self.publisher), "witness.pkcs8.pem": pem(self.witness),
            "admin.pkcs8.pem": pem(self.admin), "node.pkcs8.pem": pem(self.node),
            "admin.pub.b64": b64(public(self.admin)), "fetch-token": self.fetch_token,
        }.items():
            protected_write(self.root / name, data)
        protected_write(self.root / "private-context.json", canonical({
            "scope": self.scope, "installation_id": self.installation_id, "binding_id": self.binding_id,
            "read_key": b64(self.read_key), "owner_password": self.owner_password, "db_password": self.db_password,
            "jwt_secret": self.jwt_secret, "root_key": self.root_key,
            "panel_origin": self.panel_origin, "witness_origin": self.witness_origin,
        }))

    @classmethod
    def load(cls, task_dir):
        # Explicit developer recovery of this disposable test fixture only.
        task_dir = cls.safe_task(task_dir)
        instance = cls.__new__(cls)
        instance.root = task_dir / "private"
        context = json.loads((instance.root / "private-context.json").read_text())
        for name, value in context.items():
            if name != "read_key":
                setattr(instance, name, value)
        instance.read_key = base64.urlsafe_b64decode(context["read_key"] + "=")
        for attribute, filename in (("publisher", "publisher.pkcs8.pem"), ("witness", "witness.pkcs8.pem"),
                                    ("admin", "admin.pkcs8.pem"), ("node", "node.pkcs8.pem")):
            setattr(instance, attribute, serialization.load_pem_private_key((instance.root / filename).read_bytes(), password=None))
        instance.fetch_token = (instance.root / "fetch-token").read_text()
        instance.panel_ca = (instance.root / "panel-ca.crt").read_bytes()
        instance.witness_ca = (instance.root / "witness-ca.crt").read_bytes()
        return instance

    def __repr__(self):
        return "<ephemeral test authority [redacted]>"

    @property
    def node_public(self):
        return self.node.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    @property
    def node_fingerprint(self):
        return "p256-sha256:" + hashlib.sha256(self.node_public).hexdigest()

    def genesis(self):
        body = {"format": "sekvyr-witness-genesis-v1", **self.scope,
                "panel_origin": self.panel_origin, "witness_epoch": "1",
                "witness_public_key": b64(public(self.witness)), "witness_key_id": key_id(self.witness),
                "publisher_policy_epoch": "1", "publisher_keys": [{"key_id": key_id(self.publisher), "public_key": b64(public(self.publisher))}],
                "read_key_epoch": "1", "admin_key_id": key_id(self.admin)}
        registration = {"body": body, "signature": b64(self.admin.sign(domain("witness-genesis") + canonical(body)))}
        digest = hashlib.sha256(domain("witness-genesis-hash") + canonical(registration)).hexdigest()
        return registration, digest

    def snapshot(self, sequence, previous_hash, generation, demo_value):
        entries = [{"path": "/runtime", "name": "DEMO_VALUE", "value": demo_value},
                   {"path": "/runtime", "name": "GENERATION", "value": generation}]
        header = {"protocol": "e2e2", "suite": "HKDF-SHA256+A256GCM+Ed25519", "intent": "publish", **self.scope,
                  "sequence": str(sequence), "previous_hash": previous_hash, "read_key_epoch": "1",
                  "publisher_policy_epoch": "1", "publisher_key_id": key_id(self.publisher),
                  "snapshot_salt": b64(os.urandom(32)), "entry_count": len(entries),
                  "action": "initial" if sequence == 1 else "update", "restored_from": None, "parents": []}
        salt = base64.urlsafe_b64decode(header["snapshot_salt"] + "=")
        nonce = os.urandom(12)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                   info=domain("snapshot-key") + canonical(header)).derive(self.read_key)
        payload = {"format": "sekvyr-e2e2-values-v1", "context": self.scope, "entries": entries}
        ciphertext = AESGCM(key).encrypt(nonce, canonical(payload), domain("snapshot-aad") + canonical(header))
        body = {"header": header, "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        envelope = {"body": body, "signature": b64(self.publisher.sign(domain("publish") + canonical(body)))}
        digest = hashlib.sha256(domain("envelope-hash") + canonical(envelope)).hexdigest()
        return envelope, digest

    def reader_wrap(self):
        context = {"protocol": "e2e2-reader-key-v1", **self.scope, "read_key_epoch": "1",
                   "publisher_policy_epoch": "1", "publisher_key_id": key_id(self.publisher),
                   "recipient_fingerprint": self.node_fingerprint}
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        shared = ephemeral.exchange(ec.ECDH(), self.node.public_key())
        salt, nonce = os.urandom(32), os.urandom(12)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                   info=domain("reader-wrap-key") + canonical(context)).derive(shared)
        payload = {"format": "sekvyr-e2e2-read-key-v1", "context": context, "read_key": b64(self.read_key)}
        ciphertext = AESGCM(key).encrypt(nonce, canonical(payload), domain("reader-wrap-aad") + canonical(context))
        body = {"context": context, "ephemeral_public": b64(ephemeral.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
                "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        return {"body": body, "signature": b64(self.publisher.sign(domain("reader-wrap-sign") + canonical(body)))}

    def trust_bundle(self, store_uid, minimum_hash, namespace="stage4-apps", service_account="sekvyr-operator"):
        return {"schemaVersion": 2, "installationID": self.installation_id, "bootstrapGeneration": 1,
                "namespace": namespace, "serviceAccount": service_account, "panelOrigin": self.panel_origin,
                "nodePublicKeyFingerprint": self.node_fingerprint,
                "viewTrust": [{"trustKey": "runtime-view", "storeUID": store_uid, "bindingID": self.binding_id,
                               "realmID": self.scope["realm_id"], "projectID": self.scope["project_id"],
                               "environmentID": self.scope["environment_id"], "viewID": self.scope["view_id"], "logID": self.scope["log_id"],
                               "publisherPolicyEpoch": "1", "publisherPublicKey": b64(public(self.publisher)),
                               "publisherKeyFingerprint": key_id(self.publisher),
                               "witness": {"origin": self.witness_origin, "epoch": "1", "publicKey": b64(public(self.witness)), "keyFingerprint": key_id(self.witness)},
                               "minimumCheckpoint": {"sequence": "1", "envelopeHash": minimum_hash}}]}
