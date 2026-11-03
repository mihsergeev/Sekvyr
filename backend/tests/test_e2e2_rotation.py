"""Actual panel/DB + real mTLS + signed public authority protocol fixtures.

The TLS peer tests the authority wire boundary. Go/live tests cover the actual
canonical journal. All publisher/read/scalar material here is synthetic public.
"""
import base64
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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from app import e2e2, e2e2_rotation
from app.models import E2E2AuthorityProjection, E2E2EpochReaderGrant, E2E2StagedReaderWrap
from tests.conftest import login
from tests.test_e2e2 import add_reader, machine_for, register_view, vectors
from tests.test_e2e2_index import public_material


def private(label):
    return ed25519.Ed25519PrivateKey.from_private_bytes(public_material(label))


def public(label):
    raw = private(label).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"key_id": e2e2.key_id(raw), "public_key": e2e2.b64(raw)}


def envelope(vector, sequence, previous, read_epoch, read_key):
    value = copy.deepcopy(vector["envelope"])
    h = value["body"]["header"]
    h.update(sequence=sequence, previous_hash=previous, read_key_epoch=read_epoch, publisher_policy_epoch="2", publisher_key_id=public("publisher-2")["key_id"], action="rotate-read-key" if read_epoch == "2" else "update", snapshot_salt=e2e2.b64(os.urandom(32)))
    context = e2e2.canonical(h)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=e2e2.binary(h["snapshot_salt"], 32), info=b"sekvyr-e2e2/snapshot-key/v1\0" + context).derive(read_key)
    nonce = os.urandom(12)
    plain = copy.deepcopy(vector["plaintext"])
    plain["entries"][0]["value"] = "public-rotation-canary"
    value["body"]["nonce"] = e2e2.b64(nonce)
    value["body"]["ciphertext"] = e2e2.b64(AESGCM(key).encrypt(nonce, e2e2.canonical(plain), b"sekvyr-e2e2/snapshot-aad/v1\0" + context))
    value["signature"] = e2e2.b64(private("publisher-2").sign(b"sekvyr-e2e2/publish/v1\0" + e2e2.canonical(value["body"])))
    return value


def reader_wrap(vector, read_key):
    body = copy.deepcopy(vector["wrapper"]["body"])
    context = body["context"]
    context.update(read_key_epoch="2", publisher_policy_epoch="2", publisher_key_id=public("publisher-2")["key_id"])
    recipient = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), e2e2.binary(vector["node_public_key"], 65))
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    body["ephemeral_public"] = e2e2.b64(ephemeral.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    salt, nonce = os.urandom(32), os.urandom(12)
    body["salt"], body["nonce"] = e2e2.b64(salt), e2e2.b64(nonce)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"sekvyr-e2e2/reader-wrap-key/v1\0" + e2e2.canonical(context)).derive(ephemeral.exchange(ec.ECDH(), recipient))
    payload = {"format": "sekvyr-e2e2-read-key-v1", "context": context, "read_key": e2e2.b64(read_key)}
    body["ciphertext"] = e2e2.b64(AESGCM(key).encrypt(nonce, e2e2.canonical(payload), b"sekvyr-e2e2/reader-wrap-aad/v1\0" + e2e2.canonical(context)))
    return {"body": body, "signature": e2e2.b64(private("publisher-2").sign(b"sekvyr-e2e2/reader-wrap-sign/v1\0" + e2e2.canonical(body)))}


@pytest.fixture
def authority_peer(tmp_path, monkeypatch):
    vector, wrap = vectors()
    scope = {field: vector["envelope"]["body"]["header"][field] for field in e2e2.SCOPE}
    authority = {"revision": "1", "admin_key": public("rotation-admin"), "publisher_policy_epoch": "1", "publisher_keys": [public("publisher")], "read_key_epoch": "1", "witness_epoch": "1", "witness_key": public("witness"), "fencer_epoch": "1", "fencer_keys": [public("rotation-fencer")]}
    genesis_hash = hashlib.sha256(b"public-protocol-peer-genesis").hexdigest()
    record1 = hashlib.sha256(b"public-protocol-peer-record-1").hexdigest()
    record3 = hashlib.sha256(b"public-protocol-peer-record-3").hexdigest()
    state = {"scope": scope, "genesis_hash": genesis_hash, "cursor": {"journal_sequence": "1", "record_hash": record1}, "snapshot": {"sequence": "1", "envelope_hash": vector["envelope_hash"], "read_key_epoch": "1", "publisher_policy_epoch": "1"}, "authority": authority, "authority_digest": "", "enrollments": {}}
    peer = {"state": state, "mode": "valid", "requests": [], "signer": private("witness")}
    root_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "public-test-root")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(root_key, hashes.SHA256()))
    ca_path = tmp_path / "authority-ca.pem"
    ca_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))

    def certificate(label, usage, server=False):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])).issuer_name(root_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=1)).add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        value = builder.sign(root_key, hashes.SHA256())
        cert_path, key_path = tmp_path / (label + ".pem"), tmp_path / (label + ".key")
        cert_path.write_bytes(value.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        return cert_path, key_path

    server_cert, server_key = certificate("public-witness", ExtendedKeyUsageOID.SERVER_AUTH, True)
    client_cert, client_key = certificate("public-panel", ExtendedKeyUsageOID.CLIENT_AUTH)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            if self.path != f"/v2/logs/{scope['log_id']}/authority-challenge" or not self.connection.getpeercert():
                self.send_error(404)
                return
            request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            peer["requests"].append(request)
            current = copy.deepcopy(peer["state"])
            digest_body = {field: current[field] for field in ("scope", "genesis_hash", "authority", "enrollments")}
            current["authority_digest"] = hashlib.sha256(b"sekvyr-e2e2/authority-state-hash/v1\0" + e2e2.canonical(digest_body)).hexdigest()
            body = {"format": "sekvyr-authority-proof-v2", "state": current, "request_nonce": request["request_nonce"], "floor": request["floor"]}
            if peer["mode"] == "nonce":
                body["request_nonce"] = e2e2.b64(bytes(32))
            elif peer["mode"] == "scope":
                current["scope"]["view_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            elif peer["mode"] == "genesis":
                current["genesis_hash"] = "a" * 64
            elif peer["mode"] == "floor":
                body["floor"] = {"journal_sequence": "0", "record_hash": genesis_hash}
            signer = peer["signer"] if peer["mode"] != "signature" else private("wrong-witness")
            response = e2e2.canonical({"body": body, "key_id": current["authority"]["witness_key"]["key_id"], "signature": e2e2.b64(signer.sign(b"sekvyr-e2e2/authority-proof/v2\0" + e2e2.canonical(body)))})
            if peer["mode"] == "oversized":
                response = b"x" * (e2e2_rotation.MAX_AUTHORITY_PROOF + 1)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(server_cert), str(server_key))
    tls.load_verify_locations(str(ca_path))
    tls.verify_mode = ssl.CERT_REQUIRED
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config_path = tmp_path / "authority.json"

    def pin(label="witness", epoch="1"):
        config_path.write_text(json.dumps({"format": "sekvyr-panel-authority-config-v1", "registrations": [{"scope": scope, "genesis_hash": genesis_hash, "minimum_cursor": {"journal_sequence": "0", "record_hash": genesis_hash}, "witness_public_key": public(label)["public_key"], "witness_epoch": epoch, "witness_origin": f"https://127.0.0.1:{server.server_port}", "ca_file": str(ca_path), "client_cert_file": str(client_cert), "client_key_file": str(client_key)}]}), encoding="utf-8")
        config_path.chmod(0o600)

    read_key = public_material("view-read-2")
    second = envelope(vector, "2", vector["envelope_hash"], "1", public_material("view-read"))
    second_hash = e2e2.staged_envelope(e2e2.canonical(second), scope)[2]
    third = envelope(vector, "3", second_hash, "2", read_key)
    third_hash = e2e2.staged_envelope(e2e2.canonical(third), scope)[2]
    peer.update(vector=vector, wrap=wrap, future=third, future_hash=third_hash, future_wrap=reader_wrap(wrap, read_key), pin=pin, config_path=config_path)

    def advance():
        state["authority"].update(revision="3", publisher_policy_epoch="2", publisher_keys=[public("publisher-2")], read_key_epoch="2")
        state["snapshot"] = {"sequence": "3", "envelope_hash": third_hash, "read_key_epoch": "2", "publisher_policy_epoch": "2"}
        state["cursor"] = {"journal_sequence": "3", "record_hash": record3}

    peer["advance"] = advance
    pin()
    monkeypatch.setenv("SEKVYR_E2E2_AUTHORITY_CONFIG_FILE", str(config_path))
    try:
        yield peer
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


async def test_future_stage_does_not_grant_then_fresh_projection_promotes_epochs(client, owner_headers, env_id, authority_peer):
    peer = authority_peer
    registered = await register_view(client, owner_headers, env_id)
    view = registered["context"]["view_id"]
    route = f"/api/e2e2/views/{view}"
    machine, machine_headers = await machine_for(client, owner_headers, env_id)
    await add_reader(client, owner_headers, machine, machine_headers, view)
    assert (await client.post(route + "/envelopes", headers=owner_headers, json=peer["vector"]["envelope"])).status_code == 201
    assert (await client.post(route + "/rotation-project", headers=owner_headers, json={})).status_code == 200
    payload = {"envelope": peer["future"], "readers": [{"machine_id": machine["id"], "wrapper": peer["future_wrap"]}]}
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json=payload)).status_code == 201
    assert (await client.post(route + "/envelopes", headers=owner_headers, json=peer["future"])).json()["reason"] == "UnsupportedEpoch"
    target = f"/api/v1/machine/e2e2/views/{view}/envelopes/{peer['future_hash']}"
    assert (await client.get(target, headers=machine_headers)).status_code in (400, 409)
    async with client._transport.app.state.session_factory() as session:
        assert await session.get(E2E2EpochReaderGrant, (view, machine["id"], "2", "2")) is None
        assert await session.get(E2E2StagedReaderWrap, (view, machine["id"], "2", "2")) is not None
    peer["advance"]()
    projected = await client.post(route + "/rotation-project", headers=owner_headers, json={})
    assert projected.status_code == 200 and projected.json()["readers_promoted"] == 1
    assert (await client.get(target, headers=machine_headers)).status_code == 200
    wrapped = await client.get(f"/api/v1/machine/e2e2/views/{view}/reader-wrap", headers=machine_headers, params={"envelope_hash": peer["future_hash"]})
    assert wrapped.status_code == 200 and wrapped.json() == peer["future_wrap"]
    # Verify the generated fixture is an actual browser-compatible encrypted wrap.
    body = wrapped.json()["body"]
    scalar = int.from_bytes(e2e2.binary(peer["wrap"]["public_test_node_scalar"], 32), "big")
    node = ec.derive_private_key(scalar, ec.SECP256R1())
    point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), e2e2.binary(body["ephemeral_public"], 65))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=e2e2.binary(body["salt"], 32), info=b"sekvyr-e2e2/reader-wrap-key/v1\0" + e2e2.canonical(body["context"])).derive(node.exchange(ec.ECDH(), point))
    payload_plain = json.loads(AESGCM(key).decrypt(e2e2.binary(body["nonce"], 12), e2e2.binary(body["ciphertext"]), b"sekvyr-e2e2/reader-wrap-aad/v1\0" + e2e2.canonical(body["context"])))
    assert payload_plain["read_key"] == e2e2.b64(public_material("view-read-2"))
    async with client._transport.app.state.session_factory() as session:
        assert await session.get(E2E2EpochReaderGrant, (view, machine["id"], "1", "1")) is not None
        assert await session.get(E2E2EpochReaderGrant, (view, machine["id"], "2", "2")) is not None
    assert (await client.delete(route + f"/readers/{machine['id']}", headers=owner_headers)).status_code == 204
    assert (await client.get(target, headers=machine_headers)).status_code == 403


async def test_projection_rejects_adversarial_proofs_and_old_pin_rollback(client, owner_headers, env_id, authority_peer):
    peer = authority_peer
    view = (await register_view(client, owner_headers, env_id))["context"]["view_id"]
    route = f"/api/e2e2/views/{view}"
    assert (await client.post(route + "/envelopes", headers=owner_headers, json=peer["vector"]["envelope"])).status_code == 201
    for mode in ("nonce", "scope", "genesis", "signature", "oversized"):
        peer["mode"] = mode
        response = await client.post(route + "/rotation-project", headers=owner_headers, json={})
        assert response.status_code in (400, 409, 503)
        assert (await client.get(route, headers=owner_headers)).json()["indexed_sequence"] == "0"
    peer["mode"] = "valid"
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json={"envelope": peer["future"], "readers": []})).status_code == 201
    peer["advance"]()
    assert (await client.post(route + "/rotation-project", headers=owner_headers, json={})).status_code == 200
    for mode in ("floor",):
        peer["mode"] = mode
        assert (await client.post(route + "/rotation-project", headers=owner_headers, json={})).status_code == 409
    peer["mode"] = "valid"
    state = peer["state"]
    state["authority"].update(revision="4", witness_epoch="2", witness_key=public("witness-2"))
    state["cursor"] = {"journal_sequence": "4", "record_hash": hashlib.sha256(b"public-record-4").hexdigest()}
    peer["signer"] = private("witness-2")
    peer["pin"]("witness-2", "2")
    assert (await client.post(route + "/rotation-project", headers=owner_headers, json={})).status_code == 200
    peer["pin"]("witness", "1")
    before = len(peer["requests"])
    denied = await client.post(route + "/rotation-project", headers=owner_headers, json={})
    assert denied.status_code == 409 and denied.json()["reason"] == "AuthorityDowngrade"
    assert len(peer["requests"]) == before
    async with client._transport.app.state.session_factory() as session:
        record = await session.get(E2E2AuthorityProjection, view)
        assert record.journal_sequence == "4" and record.witness_epoch == "2"


async def test_rotation_stage_access_scope_oversize_and_old_node_fingerprint(client, owner_headers, env_id, authority_peer):
    peer = authority_peer
    view = (await register_view(client, owner_headers, env_id))["context"]["view_id"]
    route = f"/api/e2e2/views/{view}"
    machine, machine_headers = await machine_for(client, owner_headers, env_id)
    await add_reader(client, owner_headers, machine, machine_headers, view)
    payload = {"envelope": peer["future"], "readers": [{"machine_id": machine["id"], "wrapper": peer["future_wrap"]}]}
    assert (await client.post(route + "/rotation-stage", json=payload)).status_code == 401
    assert (await client.post("/api/users", headers=owner_headers, json={"username": "rotation-reader", "password": "public-test-pass-2026", "role": "viewer"})).status_code == 201
    viewer = await login(client, "rotation-reader", "public-test-pass-2026")
    assert (await client.post(route + "/rotation-stage", headers=viewer, json=payload)).status_code == 403
    cross_view = copy.deepcopy(payload)
    cross_view["envelope"]["body"]["header"]["view_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json=cross_view)).status_code == 400
    oversized = copy.deepcopy(payload)
    oversized["envelope"]["body"]["ciphertext"] = "A" * e2e2.MAX_ENVELOPE
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json=oversized)).status_code == 413
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json=payload)).status_code == 201
    replacement = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert (await client.post("/api/v1/machine/report", headers=machine_headers, json={"public_key": base64.b64encode(replacement).decode()})).status_code == 200
    peer["advance"]()
    denied = await client.post(route + "/rotation-project", headers=owner_headers, json={})
    assert denied.status_code == 409 and denied.json()["reason"] == "AwaitingProjectKey"
    assert (await client.get(route, headers=owner_headers)).json()["indexed_sequence"] == "0"
    async with client._transport.app.state.session_factory() as session:
        assert await session.get(E2E2EpochReaderGrant, (view, machine["id"], "2", "2")) is None


async def test_rotation_never_trusts_incoming_keys_or_bad_wrapper_signature(client, owner_headers, env_id, authority_peer):
    peer = authority_peer
    view = (await register_view(client, owner_headers, env_id))["context"]["view_id"]
    route = f"/api/e2e2/views/{view}"
    machine, machine_headers = await machine_for(client, owner_headers, env_id)
    await add_reader(client, owner_headers, machine, machine_headers, view)
    payload = {"envelope": peer["future"], "readers": [{"machine_id": machine["id"], "wrapper": copy.deepcopy(peer["future_wrap"])}]}
    incoming_keys = {**payload, "publisher_keys": {public("publisher-2")["key_id"]: public("publisher-2")["public_key"]}}
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json=incoming_keys)).status_code == 400
    payload["readers"][0]["wrapper"]["signature"] = e2e2.b64(bytes(64))
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json=payload)).status_code == 201
    peer["advance"]()
    rejected = await client.post(route + "/rotation-project", headers=owner_headers, json={})
    assert rejected.status_code == 400 and rejected.json()["reason"] == "SignatureInvalid"
    async with client._transport.app.state.session_factory() as session:
        assert await session.get(E2E2EpochReaderGrant, (view, machine["id"], "2", "2")) is None
        assert await session.get(E2E2AuthorityProjection, view) is None


async def test_bad_envelope_and_same_cursor_fork_never_change_projection(client, owner_headers, env_id, authority_peer):
    peer = authority_peer
    view = (await register_view(client, owner_headers, env_id))["context"]["view_id"]
    route = f"/api/e2e2/views/{view}"
    broken = copy.deepcopy(peer["future"])
    broken["signature"] = e2e2.b64(bytes(64))
    response = await client.post(route + "/rotation-stage", headers=owner_headers, json={"envelope": broken, "readers": []})
    assert response.status_code == 201
    peer["advance"]()
    peer["state"]["snapshot"]["envelope_hash"] = response.json()["envelope_hash"]
    rejected = await client.post(route + "/rotation-project", headers=owner_headers, json={})
    assert rejected.status_code == 400 and rejected.json()["reason"] == "SignatureInvalid"
    assert (await client.get(route, headers=owner_headers)).json()["indexed_sequence"] == "0"
    peer["state"]["snapshot"]["envelope_hash"] = peer["future_hash"]
    assert (await client.post(route + "/rotation-stage", headers=owner_headers, json={"envelope": peer["future"], "readers": []})).status_code == 201
    assert (await client.post(route + "/rotation-project", headers=owner_headers, json={})).status_code == 200
    expected_hash = peer["state"]["cursor"]["record_hash"]
    peer["state"]["cursor"]["record_hash"] = "c" * 64
    assert (await client.post(route + "/rotation-project", headers=owner_headers, json={})).status_code == 409
    async with client._transport.app.state.session_factory() as session:
        projection = await session.get(E2E2AuthorityProjection, view)
        assert projection.record_hash == expected_hash
