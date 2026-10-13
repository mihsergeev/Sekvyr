"""Восьмой проход, четвертый круг: восстановление снимка и время правки.

Перенос значения из чужой папки решается в момент переноса, под блокировкой:
проверка заранее ошибалась в порядке шагов и проигрывала гонку с записью.
"""

import asyncio

import httpx

from app import secrets_store
from app.models import Secret
from tests.conftest import login
from tests.test_pass8b_backend import PASS, _pol, _project, _put, _user, _value


async def _rename(client, headers, env, path, name, new_path, new_name):
    r = await client.post(
        f"/api/environments/{env}/secret/rename",
        headers=headers,
        json={"path": path, "name": name, "new_path": new_path, "new_name": new_name},
    )
    assert r.status_code == 200, r.text


async def _snap(client, headers, env, name="s0"):
    r = await client.post(f"/api/environments/{env}/snapshots", headers=headers, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _places(client, headers, env):
    rows = (await client.get(f"/api/environments/{env}/secrets", headers=headers)).json()
    return {(r["path"], r["name"]) for r in rows}


async def test_restore_order_frees_the_place_no_false_refusal(client: httpx.AsyncClient, owner_headers, unsealed):
    """Шаг B освобождает место раньше шага A: A возвращается в свою же папку,
    переноса нет - и отказа быть не должно."""
    _pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "PAY", "old-private", path="/private")
    await _put(client, owner_headers, prod, "Z", "other-val", path="/other")
    sid = await _snap(client, owner_headers, prod)
    await _rename(client, owner_headers, prod, "/private", "PAY", "/z", "PUB")
    await _rename(client, owner_headers, prod, "/other", "Z", "/private", "PAY")
    uid = await _user(client, owner_headers, "w", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read", "write", "delete"])
    await _pol(client, owner_headers, uid, prod, "/private", ["read"], allow=False)
    writer = await login(client, "w", PASS)
    res = await client.post(f"/api/environments/{prod}/snapshots/{sid}/restore", headers=writer)
    assert res.status_code == 200, res.text
    places = await _places(client, owner_headers, prod)
    assert ("/private", "PAY") in places and ("/other", "Z") in places and ("/z", "PUB") not in places
    assert await _value(client, owner_headers, prod, "PAY", path="/private") == "old-private"


async def test_restore_checks_the_crossing_at_the_moment(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    """Место заняли после проверок (параллельная запись): значение закрытой
    папки все равно не уходит под нынешнее имя."""
    _pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "PAY", "old-private-value", path="/private")
    sid = await _snap(client, owner_headers, prod)
    await _put(client, owner_headers, prod, "PAY", "new-private-value", path="/private")
    await _rename(client, owner_headers, prod, "/private", "PAY", "/", "PUB")
    await _put(client, owner_headers, prod, "PUB", "public-now")
    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read", "write"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"], allow=False)
    writer = await login(client, "writer", PASS)
    real = secrets_store.snapshot_removals

    async def removals_then_concurrent_put(session, snapshot):
        out = await real(session, snapshot)
        session.add(Secret(environment_id=snapshot.environment_id, path="/private", name="PAY", current_version=0))
        await session.flush()
        return out

    monkeypatch.setattr(secrets_store, "snapshot_removals", removals_then_concurrent_put)
    res = await client.post(f"/api/environments/{prod}/snapshots/{sid}/restore", headers=writer)
    assert res.status_code == 403, res.text
    assert await _value(client, writer, prod, "PUB") == "public-now"


async def test_last_change_at_skips_closed_folders(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "A", "v")
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"], allow=False)
    dev = await login(client, "dev", PASS)
    before = next(p for p in (await client.get("/api/projects", headers=dev)).json() if p["id"] == pid)["last_change_at"]
    await asyncio.sleep(1.1)
    await _put(client, owner_headers, prod, "HIDDEN", "x", path="/private")
    after = next(p for p in (await client.get("/api/projects", headers=dev)).json() if p["id"] == pid)["last_change_at"]
    assert before == after


async def test_e2e_needs_the_whole_project(client: httpx.AsyncClient, owner_headers, unsealed):
    """Шифрование в браузере - на весь проект: права на одно окружение мало."""
    res = await client.post("/api/projects", headers=owner_headers, json={"slug": "vault2", "environments": ["dev", "prod"]})
    pid = res.json()["id"]
    envs = {e["name"]: e["id"] for e in (await client.get(f"/api/projects/{pid}/environments", headers=owner_headers)).json()}
    uid = await _user(client, owner_headers, "stagelead", "maintainer")
    await _pol(client, owner_headers, uid, envs["dev"], "/", ["list", "read", "write"])
    lead = await login(client, "stagelead", PASS)
    body = {"salt": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAAAAAAA", "wrapped_key": "A" * 64,
            "verifier_nonce": "AAAAAAAAAAAAAAAA", "verifier": "A" * 64}
    res = await client.post(f"/api/projects/{pid}/e2e", headers=lead, json=body)
    assert res.status_code == 403, res.text
    project = next(p for p in (await client.get("/api/projects", headers=owner_headers)).json() if p["id"] == pid)
    assert project["e2e"] is False
