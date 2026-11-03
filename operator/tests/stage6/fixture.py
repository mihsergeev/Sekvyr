"""Ephemeral trial identities; no private material belongs in the source tree."""

import base64
import json
import os
from pathlib import Path
import re
import tempfile
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROLES = ("storage", "gateway", "witness", "fencer", "apps", "panel", "foreign")


def safe_task(value):
    path = Path(value).absolute()
    if path.resolve() != path:
        raise ValueError("Trial directory must not contain symlinks")
    server = path.parent == Path("/opt/sekvyr-trial") and re.fullmatch(r"sekvyr-stage6-[0-9]{8}-[0-9a-f]{8}", path.name)
    local_parent = Path(tempfile.gettempdir()).resolve()
    local = path.parent == local_parent and re.fullmatch(r"sekvyr-stage6\.[A-Za-z0-9_-]+", path.name)
    if not (server or local):
        raise ValueError("Unapproved trial directory")
    return path


def write_private(path, content):
    path = Path(path)
    raw = content.encode("utf-8") if isinstance(content, str) else content
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def token(size=32):
    return base64.urlsafe_b64encode(os.urandom(size)).decode("ascii").rstrip("=")


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def issue_leaf(task, authority, label, usage, hostnames=()):
    """Offline fixture extension, with no overwriting existing keys or certs."""
    if authority not in ("storage", "journal") or usage not in ("server", "client") or not re.fullmatch(r"[a-z][a-z0-9-]{0,40}", label):
        raise ValueError("Invalid trial leaf identity")
    private = safe_task(task) / "private"
    ca_key = serialization.load_pem_private_key((private / (authority + "-ca.key")).read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((private / (authority + "-ca.crt")).read_bytes())
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-trial-" + label)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if usage == "server" else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True))
    if hostnames:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in hostnames]), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    write_private(private / (label + ".key"), pem(key))
    write_private(private / (label + ".crt"), cert.public_bytes(serialization.Encoding.PEM))


class TrialFixture:
    def __init__(self, task):
        self.task = safe_task(task)
        self.private = self.task / "private"
        self.private.mkdir(mode=0o700)
        self.prefix = self.task.name.replace(".", "-").replace("_", "-").lower()
        if len(self.prefix) > 45:
            raise ValueError("Trial namespace prefix too long")
        self.namespaces = {role: self.prefix + "-" + role for role in ROLES}
        self.bucket = "canonical-trial-ledger"
        self.storage_credentials = {
            "admin": {"access_key": token(18), "secret_key": token(36)},
            "gateway": {"access_key": token(18), "secret_key": token(36)},
        }
        self._tls()
        # These files are consumed only by offline bootstrap / the gateway mount.
        write_private(self.private / "storage-credentials.json", canonical(self.storage_credentials))
        identities = []
        for name, actions in (("trial-storage-admin", ["Admin"]),
                              ("trial-journal-gateway", [action + ":" + self.bucket for action in (
                                  "Read", "Write", "List", "GetObjectRetention", "PutObjectRetention",
                                  "GetBucketVersioning", "GetBucketObjectLockConfiguration")])):
            role = "admin" if name.endswith("admin") else "gateway"
            cred = self.storage_credentials[role]
            identities.append({"name": name, "credentials": [{"accessKey": cred["access_key"], "secretKey": cred["secret_key"]}], "actions": actions})
        write_private(self.private / "s3-identities.json", canonical({"identities": identities}))
        write_private(self.private / "fixture.json", canonical({"format": "sekvyr-stage6-trial-v1", "namespaces": self.namespaces,
            "bucket": self.bucket, "production": False}))

    def __repr__(self):
        return "<stage6 trial fixture [redacted]>"

    def _tls(self):
        now = datetime.now(timezone.utc)
        for authority, leaves in {
            "storage": [("storage", "server", ["s3." + self.namespaces["storage"] + ".svc.cluster.local", "localhost"])],
            "journal": [("journal", "server", ["journal." + self.namespaces["gateway"] + ".svc.cluster.local", "localhost"]),
                        ("witness-a", "client", []), ("witness-b", "client", []),
                        ("fencer", "client", []), ("operator", "client", []), ("panel", "client", []),
                        ("admin", "client", []), ("unregistered", "client", [])],
        }.items():
            ca_key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-trial-" + authority + "-ca")])
            ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                       .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                       .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                       .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
                       .sign(ca_key, hashes.SHA256()))
            write_private(self.private / (authority + "-ca.crt"), ca_cert.public_bytes(serialization.Encoding.PEM))
            # CA signing key remains exclusively in this offline private fixture.
            write_private(self.private / (authority + "-ca.key"), pem(ca_key))
            for label, usage, hosts in leaves:
                key = ec.generate_private_key(ec.SECP256R1())
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-trial-" + label)])
                builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(key.public_key())
                           .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                           .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                           .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if usage == "server" else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True))
                if hosts:
                    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in hosts]), critical=False)
                certificate = builder.sign(ca_key, hashes.SHA256())
                write_private(self.private / (label + ".crt"), certificate.public_bytes(serialization.Encoding.PEM))
                write_private(self.private / (label + ".key"), pem(key))
