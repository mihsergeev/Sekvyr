"""Actual panel ASGI/database checks using only public synthetic protocol vectors."""
import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from app import e2e2

ROOT = Path(__file__).resolve().parents[2]


def vectors():
    snapshot = json.loads((ROOT / "operator/design/e2e2.public-vectors.json").read_text(encoding="utf-8"))
    wrapper = json.loads((ROOT / "operator/tests/e2e2/public-reader-wrap-vector.json").read_text(encoding="utf-8"))
    return snapshot, wrapper


async def register_view(client, headers, env_id):
    snapshot, _ = vectors()
    project = next(row for row in (await client.get("/api/projects", headers=headers)).json() if row["slug"] == "billing")
    h = snapshot["envelope"]["body"]["header"]
    response = await client.post("/api/e2e2/views", headers=headers, json={
        "project_id": project["id"], "environment_id": env_id,
        "context": {name: h[name] for name in e2e2.SCOPE},
        "publisher_keys": {h["publisher_key_id"]: snapshot["publisher_public_key"]},
        "read_key_epoch": "1", "publisher_policy_epoch": "1"})
    assert response.status_code == 201
    return response.json()


async def machine_for(client, headers, env_id):
    response = await client.post("/api/machines", headers=headers, json={"name": "e2e2-reader"})
    assert response.status_code == 201
    machine = response.json()
    response = await client.post("/api/policies", headers=headers, json={
        "subject_type": "machine", "subject_id": machine["id"], "environment_id": env_id,
        "path_prefix": "/", "actions": ["read"], "effect": "allow"})
    assert response.status_code == 201
    token = await client.post("/api/v1/machine/token", json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]})
    assert token.status_code == 200
    head = {"Authorization": "Bearer " + token.json()["access_token"]}
    return machine, head


async def add_reader(client, headers, machine, machine_headers, view):
    _, vector = vectors()
    public = e2e2.binary(vector["node_public_key"], 65)
    report = await client.post("/api/v1/machine/report", headers=machine_headers, json={"public_key": base64.b64encode(public).decode()})
    assert report.status_code == 200
    response = await client.post(f"/api/e2e2/views/{view}/readers", headers=headers, json={"machine_id": machine["id"], "wrapper": vector["wrapper"]})
    assert response.status_code == 200


def test_public_vectors_and_strict_canonical_validation():
    vector, wrapper = vectors()
    h = vector["envelope"]["body"]["header"]
    scope = {name: h[name] for name in e2e2.SCOPE}
    keys = {h["publisher_key_id"]: vector["publisher_public_key"]}
    _, encoded, digest = e2e2.validate_envelope(e2e2.canonical(vector["envelope"]), scope, keys)
    assert digest == vector["envelope_hash"]
    assert e2e2.canonical(json.loads(encoded)["body"]) == e2e2.binary(vector["canonical_body_base64url"])
    assert e2e2.canonical(wrapper["unicode_case"]) == e2e2.binary(wrapper["unicode_canonical_base64url"])
    fingerprint = "p256-sha256:" + hashlib.sha256(e2e2.binary(wrapper["node_public_key"], 65)).hexdigest()
    assert e2e2.validate_wrapper(e2e2.canonical(wrapper["wrapper"]), scope, fingerprint, keys)
    for raw in (b'{"a":1,"\\u0061":2}', b'{"a":"\\ud800"}', b'{"a":1.0}', b'{"a":1e0}', b'{"a":-0}', b'\xef\xbb\xbf{}', b'{"a":"\xff"}'):
        with pytest.raises(e2e2.Rejected):
            e2e2.load(raw, 4096)
    broken = copy.deepcopy(vector["envelope"])
    del broken["body"]["header"]["restored_from"]
    with pytest.raises(e2e2.Rejected):
        e2e2.validate_envelope(e2e2.canonical(broken), scope, keys)


async def test_staged_immutable_hash_fetch_and_explicit_grant(client, owner_headers, env_id, monkeypatch):
    vector, _ = vectors()
    registered = await register_view(client, owner_headers, env_id)
    view, digest = registered["context"]["view_id"], vector["envelope_hash"]
    machine, head = await machine_for(client, owner_headers, env_id)
    route = f"/api/e2e2/views/{view}/envelopes"
    response = await client.post(route, headers=owner_headers, json=vector["envelope"])
    assert response.status_code == 201 and response.json()["envelope_hash"] == digest
    assert (await client.post(route, headers=owner_headers, json=vector["envelope"])).status_code == 201
    target = f"/api/v1/machine/e2e2/views/{view}/envelopes/{digest}"
    assert (await client.get(target, headers=head)).status_code == 403
    await add_reader(client, owner_headers, machine, head, view)
    response = await client.get(target, headers=head)
    assert response.status_code == 200 and response.json() == vector["envelope"]
    response = await client.get(f"/api/v1/machine/e2e2/views/{view}/reader-wrap", headers=head, params={"envelope_hash": digest})
    assert response.status_code == 200
    # An exact hash never falls back to current or another view's data.
    assert (await client.get(target[:-64] + "b" * 64, headers=head)).status_code == 404
    other = copy.deepcopy(vector["envelope"])
    other["body"]["header"]["entry_count"] = 0
    rejected = await client.post(route, headers=owner_headers, json=other)
    assert rejected.status_code == 400 and rejected.json()["reason"] == "SignatureInvalid"
    assert (await client.get(target, headers=head)).json() == vector["envelope"]
    # Capability does not claim E2E2 without administrative witness configuration.
    monkeypatch.delenv("SEKVYR_E2E2_WITNESS_ORIGIN", raising=False)
    assert "e2e2" not in (await client.get("/api/v1/machine/capabilities", headers=head)).json()["protocols"]
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_ORIGIN", "https://witness.example.test")
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_PUBLIC_KEY", vector["witness_public_key"])
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_EPOCH", "1")
    assert "e2e2" in (await client.get("/api/v1/machine/capabilities", headers=head)).json()["protocols"]


async def test_explicit_grant_does_not_override_folder_denies_or_revoke(client, owner_headers, env_id):
    registered = await register_view(client, owner_headers, env_id)
    view = registered["context"]["view_id"]
    vector, _ = vectors()
    await client.post(f"/api/e2e2/views/{view}/envelopes", headers=owner_headers, json=vector["envelope"])
    machine, head = await machine_for(client, owner_headers, env_id)
    await add_reader(client, owner_headers, machine, head, view)
    target = f"/api/v1/machine/e2e2/views/{view}/envelopes/{vector['envelope_hash']}"
    denied = await client.post("/api/policies", headers=owner_headers, json={
        "subject_type": "machine", "subject_id": machine["id"], "environment_id": env_id,
        "path_prefix": "/hidden", "actions": ["read"], "effect": "deny"})
    assert denied.status_code == 201
    assert (await client.get(target, headers=head)).status_code == 403
    assert (await client.delete(f"/api/policies/{denied.json()['id']}", headers=owner_headers)).status_code == 204
    assert (await client.get(target, headers=head)).status_code == 200
    assert (await client.delete(f"/api/e2e2/views/{view}/readers/{machine['id']}", headers=owner_headers)).status_code == 204
    assert (await client.get(target, headers=head)).status_code == 403


async def test_recipient_change_cannot_reuse_signed_wrapper(client, owner_headers, env_id):
    registered = await register_view(client, owner_headers, env_id)
    view = registered["context"]["view_id"]
    vector, wrap = vectors()
    await client.post(f"/api/e2e2/views/{view}/envelopes", headers=owner_headers, json=vector["envelope"])
    machine, head = await machine_for(client, owner_headers, env_id)
    await add_reader(client, owner_headers, machine, head, view)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    changed = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert (await client.post("/api/v1/machine/report", headers=head, json={"public_key": base64.b64encode(changed).decode()})).status_code == 200
    response = await client.get(f"/api/v1/machine/e2e2/views/{view}/reader-wrap", headers=head, params={"envelope_hash": vector["envelope_hash"]})
    assert response.status_code == 409 and response.json()["reason"] == "AwaitingProjectKey"
    assert (await client.post(f"/api/e2e2/views/{view}/readers", headers=owner_headers, json={"machine_id": machine["id"], "wrapper": wrap["wrapper"]})).status_code == 400


async def test_legacy_reads_mutations_and_global_listing(client, owner_headers, env_id):
    await register_view(client, owner_headers, env_id)
    machine, head = await machine_for(client, owner_headers, env_id)
    for suffix in ("secrets", "env"):
        response = await client.get("/api/v1/machine/" + suffix, headers=head, params={"project": "billing", "env": "prod"})
        assert response.status_code == 409 and response.json()["reason"] == "UpgradeRequired"
    assert (await client.get("/api/projects", headers=owner_headers)).status_code == 200
    assert (await client.get("/api/environments", headers=owner_headers)).status_code == 200
    for method, suffix, payload in (
        ("PUT", "secrets", {"name": "A", "value": "nonsecret-canary"}),
        ("POST", "import", {"text": "A=nonsecret-canary\n"}),
        ("POST", "copy-from", {"source": "stage", "name": "A"}),
        ("POST", "secret/approve", {"name": "A", "version": 1}),
        ("POST", "snapshots/1/restore", {}),
        ("POST", "secret/rename", {"name": "A", "new_name": "B"}),
    ):
        response = await client.request(method, f"/api/environments/{env_id}/{suffix}", headers=owner_headers, json=payload)
        assert response.status_code == 409 and response.json()["reason"] == "UpgradeRequired"


async def test_emergency_export_refuses_e2e2_after_owner_reauthentication(client, owner_headers, env_id):
    from tests.conftest import OWNER_PASSWORD

    await register_view(client, owner_headers, env_id)
    payload = {"password": "public-test-archive-password", "login_password": "wrong-test-password"}
    # Existence of an E2E2 view is not disclosed before the existing password gate.
    assert (await client.post("/api/ops/emergency", headers=owner_headers, json=payload)).status_code == 403
    payload["login_password"] = OWNER_PASSWORD
    response = await client.post("/api/ops/emergency", headers=owner_headers, json=payload)
    assert response.status_code == 409
    assert response.json()["reason"] == "E2E2EmergencyExportUnsupported"
    assert "Content-Disposition" not in response.headers


async def test_body_scoped_legacy_mutation_guard_is_shared_and_precedes_network(client, owner_headers, env_id, monkeypatch):
    await register_view(client, owner_headers, env_id)
    from app.api import migrate
    called = []

    async def forbidden_fetch(_body):
        called.append(True)
        raise AssertionError("E2E2 target reached legacy network source")

    monkeypatch.setattr(migrate, "_fetch", forbidden_fetch)
    for route in ("preview", "apply"):
        response = await client.post("/api/migrate/" + route, headers=owner_headers, json={
            "source": "vault", "url": "https://vault.example.test", "token": "test-only-placeholder",
            "environment_id": env_id, "mount": "secret", "path": "example"})
        assert response.status_code == 409 and response.json()["reason"] == "UpgradeRequired"
    assert not called
    # Directly exercise the shared store boundary used by bulk imports/copies.
    from app import secrets_store
    app = client._transport.app
    async with app.state.session_factory() as session:
        with pytest.raises(e2e2.Rejected, match="UpgradeRequired"):
            await secrets_store.lock_env(session, env_id)


async def test_no_automatic_migration_of_legacy_or_pending_data(client, owner_headers, env_id):
    assert (await client.put(f"/api/environments/{env_id}/secrets", headers=owner_headers, json={"name": "A", "value": "public-canary"})).status_code == 200
    vector, _ = vectors()
    project = next(row for row in (await client.get("/api/projects", headers=owner_headers)).json() if row["slug"] == "billing")
    h = vector["envelope"]["body"]["header"]
    response = await client.post("/api/e2e2/views", headers=owner_headers, json={"project_id": project["id"], "environment_id": env_id,
        "context": {name: h[name] for name in e2e2.SCOPE}, "publisher_keys": {h["publisher_key_id"]: vector["publisher_public_key"]}, "read_key_epoch": "1", "publisher_policy_epoch": "1"})
    assert response.status_code == 409 and response.json()["reason"] == "ExplicitMigrationRequired"


async def test_scoped_witness_fetch_has_no_machine_or_admin_rights(client, owner_headers, env_id, tmp_path, monkeypatch):
    registered = await register_view(client, owner_headers, env_id)
    vector, _ = vectors()
    view, digest = registered["context"]["view_id"], vector["envelope_hash"]
    assert (await client.post(f"/api/e2e2/views/{view}/envelopes", headers=owner_headers, json=vector["envelope"])).status_code == 201
    # Ephemeral local service credential, never a repository fixture.
    import secrets
    credential = secrets.token_urlsafe(48)
    token_path = tmp_path / "witness-fetch-token"
    token_path.write_text(credential, encoding="ascii")
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_FETCH_TOKEN_FILE", str(token_path))
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_FETCH_VIEWS", view)
    headers = {"Authorization": "Bearer " + credential}
    target = f"/api/e2e2/witness/views/{view}/envelopes/{digest}"
    assert (await client.get(target, headers=headers)).status_code == 200
    assert (await client.get(target)).status_code == 401
    assert (await client.post(f"/api/e2e2/views/{view}/index", headers=headers, json={"envelope_hash": digest})).status_code == 401
    assert (await client.get(f"/api/v1/machine/e2e2/views/{view}/reader-wrap", headers=headers, params={"envelope_hash": digest})).status_code == 401
    monkeypatch.setenv("SEKVYR_E2E2_WITNESS_FETCH_VIEWS", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    assert (await client.get(target, headers=headers)).status_code == 401
