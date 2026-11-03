"""Real TLS transport and Ed25519 proof checks around the actual panel/DB API.

The local signer is a protocol test peer, not a durable witness implementation.
The separate Go/Kubernetes suite exercises the real canonical witness ledger.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID
import pytest

from app import e2e2
from app.models import E2E2View
from tests.test_e2e2 import register_view, vectors


def public_material(label):
    # PUBLIC deterministic synthetic reference material; confined to tests.
    return hashlib.sha256(("sekvyr-e2e2-public-test-vector/" + label).encode()).digest()


def next_snapshot(vector):
    snapshot = copy.deepcopy(vector["envelope"])
    h = snapshot["body"]["header"]
    h.update(sequence="2", previous_hash=vector["envelope_hash"], action="update", snapshot_salt=e2e2.b64(os.urandom(32)))
    plain = copy.deepcopy(vector["plaintext"])
    plain["entries"][0]["value"] = "public-canary-generation-2"
    context = e2e2.canonical(h)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=e2e2.binary(h["snapshot_salt"], 32), info=b"sekvyr-e2e2/snapshot-key/v1\0" + context).derive(public_material("view-read"))
    nonce = os.urandom(12)
    snapshot["body"]["nonce"] = e2e2.b64(nonce)
    snapshot["body"]["ciphertext"] = e2e2.b64(AESGCM(key).encrypt(nonce, e2e2.canonical(plain), b"sekvyr-e2e2/snapshot-aad/v1\0" + context))
    publisher = ed25519.Ed25519PrivateKey.from_private_bytes(public_material("publisher"))
    snapshot["signature"] = e2e2.b64(publisher.sign(b"sekvyr-e2e2/publish/v1\0" + e2e2.canonical(snapshot["body"])))
    return snapshot


@pytest.fixture
def signed_tls_peer(tmp_path, monkeypatch):
    vector, _ = vectors()
    header = vector["envelope"]["body"]["header"]
    scope = {name: header[name] for name in e2e2.SCOPE}
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(public_material("witness"))
    pub = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    state = {"sequence": "1", "hash": vector["envelope_hash"], "mode": "valid", "requests": []}
    tls_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-only-witness")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(tls_key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "peer-ca.pem", tmp_path / "peer-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            if self.path != f"/v1/logs/{scope['log_id']}/head-challenge":
                self.send_error(404)
                return
            size = int(self.headers.get("Content-Length", "0"))
            if size > 4096:
                self.send_error(413)
                return
            request = json.loads(self.rfile.read(size))
            state["requests"].append(request)
            body = {"format": "sekvyr-e2e2-head-v1", **scope, "witness_epoch": "1", "sequence": state["sequence"],
                "envelope_hash": state["hash"], "read_key_epoch": "1", "publisher_policy_epoch": "1",
                "request_nonce": request["request_nonce"], "witness_key_id": e2e2.key_id(pub),
                "floor_sequence": request["floor_sequence"], "floor_hash": request["floor_hash"]}
            if state["mode"] == "replayed-nonce":
                body["request_nonce"] = e2e2.b64(bytes(32))
            elif state["mode"] == "wrong-epoch":
                body["witness_epoch"] = "2"
            elif state["mode"] == "wrong-scope":
                body["view_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            signature = signer.sign(b"sekvyr-e2e2/head/v1\0" + e2e2.canonical(body))
            if state["mode"] == "wrong-signature":
                signature = ed25519.Ed25519PrivateKey.generate().sign(b"sekvyr-e2e2/head/v1\0" + e2e2.canonical(body))
            response = e2e2.canonical({"body": body, "signature": e2e2.b64(signature)})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(cert_path), str(key_path))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_ORIGIN", f"https://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_CA_FILE", str(cert_path))
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_PUBLIC_KEY", e2e2.b64(pub))
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_EPOCH", "1")
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


async def test_index_requires_fresh_signed_matching_witness_head(client, owner_headers, env_id, signed_tls_peer):
    state = signed_tls_peer
    vector, _ = vectors()
    registered = await register_view(client, owner_headers, env_id)
    view = registered["context"]["view_id"]
    route = f"/api/e2e2/views/{view}"
    staged = await client.post(route + "/envelopes", headers=owner_headers, json=vector["envelope"])
    assert staged.status_code == 201
    for mode in ("replayed-nonce", "wrong-signature", "wrong-scope", "wrong-epoch"):
        state["mode"] = mode
        response = await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": vector["envelope_hash"]})
        assert response.status_code in (400, 409)
        assert (await client.get(route, headers=owner_headers)).json()["indexed_sequence"] == "0"
    state["mode"] = "valid"
    response = await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": vector["envelope_hash"]})
    assert response.status_code == 200 and response.json()["sequence"] == "1"
    assert state["requests"][-1]["floor_sequence"] == "0"
    changed = next_snapshot(vector)
    staged = await client.post(route + "/envelopes", headers=owner_headers, json=changed)
    assert staged.status_code == 201
    digest = staged.json()["envelope_hash"]
    state["sequence"], state["hash"] = "2", digest
    response = await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": digest})
    assert response.status_code == 200 and state["requests"][-1]["floor_sequence"] == "1"
    # A valid old signed head is not enough to decrease the durable derived pointer.
    state["sequence"], state["hash"] = "1", vector["envelope_hash"]
    response = await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": vector["envelope_hash"]})
    assert response.status_code == 409 and response.json()["reason"] == "RollbackDetected"
    assert (await client.get(route, headers=owner_headers)).json()["indexed_hash"] == digest
    # A restored panel DB is not an authority to make an old indexed snapshot current.
    state["sequence"], state["hash"] = "2", digest
    app = client._transport.app
    async with app.state.session_factory() as session:
        record = await session.get(E2E2View, view)
        record.indexed_sequence, record.indexed_hash = "0", e2e2.ZERO
        await session.commit()
    response = await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": vector["envelope_hash"]})
    assert response.status_code == 409 and response.json()["reason"] == "HeadChanged"
    response = await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": digest})
    assert response.status_code == 200


async def test_missing_or_untrusted_witness_never_indexes(client, owner_headers, env_id, signed_tls_peer, monkeypatch):
    registered = await register_view(client, owner_headers, env_id)
    vector, _ = vectors()
    view = registered["context"]["view_id"]
    route = f"/api/e2e2/views/{view}"
    assert (await client.post(route + "/envelopes", headers=owner_headers, json=vector["envelope"])).status_code == 201
    monkeypatch.delenv("SEKVYR_E2E2_WITNESS_CA_FILE")
    response = await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": vector["envelope_hash"]})
    assert response.status_code == 503 and response.json()["reason"] == "WitnessUnavailable"
    assert (await client.get(route, headers=owner_headers)).json()["indexed_sequence"] == "0"
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_PUBLIC_KEY", e2e2.b64(bytes(32)))
    assert (await client.post(route + "/index", headers=owner_headers, json={"envelope_hash": vector["envelope_hash"]})).status_code != 200
