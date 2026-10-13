"""Восьмой проход, третий круг: находки ревью исправлений второго круга."""

import httpx

from tests.conftest import login
from tests.test_pass8b_backend import PASS, _child, _pol, _project, _put, _user, _value


async def _rename(client, headers, env, path, name, new_path, new_name):
    r = await client.post(
        f"/api/environments/{env}/secret/rename",
        headers=headers,
        json={"path": path, "name": name, "new_path": new_path, "new_name": new_name},
    )
    assert r.status_code == 200, r.text


async def _delete(client, headers, env, name, path="/"):
    r = await client.delete(f"/api/environments/{env}/secret", headers=headers, params={"name": name, "path": path})
    assert r.status_code == 204, r.text


# --- 1. снимок: шаг restore с занятым прежним местом кладет значение закрытой папки в открытую


async def test_snapshot_restore_busy_old_place_leaks(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "PAY", "old-private-value", path="/private")
    snap = await client.post(f"/api/environments/{prod}/snapshots", headers=owner_headers, json={"name": "s0"})
    assert snap.status_code == 201, snap.text
    sid = snap.json()["id"]
    await _put(client, owner_headers, prod, "PAY", "new-private-value", path="/private")
    await _rename(client, owner_headers, prod, "/private", "PAY", "/", "PUB")
    await _put(client, owner_headers, prod, "PUB", "public-now")
    # Прежнее место занято историей удаленного ключа: восстановление вернет
    # значение под нынешним именем, в корень.
    await _put(client, owner_headers, prod, "PAY", "tmp", path="/private")
    await _delete(client, owner_headers, prod, "PAY", path="/private")
    # Конфигурация писателя - как в test_old_value_from_closed_folder_readable.
    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read", "write"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"], allow=False)
    writer = await login(client, "writer", PASS)
    v1 = await client.get(f"/api/environments/{prod}/secret/version", headers=writer, params={"name": "PUB", "version": 1})
    assert v1.status_code == 403
    plan = (await client.get(f"/api/environments/{prod}/snapshots/{sid}/plan", headers=writer)).json()
    restore = await client.post(f"/api/environments/{prod}/snapshots/{sid}/restore", headers=writer)
    after = await _value(client, writer, prod, "PUB")
    assert after != "old-private-value", "значение, жившее только в /private, прочитано через восстановление снимка"


# --- 2. откат после переименования между видимыми папками и внутри одной


async def test_rollback_after_rename_visible_folders(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "K", "a1", path="/a")
    await _put(client, owner_headers, prod, "K", "a2", path="/a")
    await _rename(client, owner_headers, prod, "/a", "K", "/b", "K")
    await _put(client, owner_headers, prod, "K", "b1", path="/b")
    await _put(client, owner_headers, prod, "X", "x1", path="/c")
    await _put(client, owner_headers, prod, "X", "x2", path="/c")
    await _rename(client, owner_headers, prod, "/c", "X", "/c", "Y")
    uid = await _user(client, owner_headers, "w", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read", "write"])
    w = await login(client, "w", PASS)
    r1 = await client.post(f"/api/environments/{prod}/secret/rollback", headers=w, json={"name": "K", "path": "/b", "version": 1})
    r2 = await client.post(f"/api/environments/{prod}/secret/rollback", headers=w, json={"name": "Y", "path": "/c", "version": 1})
    assert r1.status_code == 200 and r2.status_code == 200
    assert await _value(client, w, prod, "K", path="/b") == "a1"
    assert await _value(client, w, prod, "Y", path="/c") == "x1"
    # Право только на /b: версия из /a закрыта.
    uid2 = await _user(client, owner_headers, "onlyb", "developer")
    await _pol(client, owner_headers, uid2, prod, "/b", ["list", "read", "write"])
    onlyb = await login(client, "onlyb", PASS)
    r3 = await client.post(f"/api/environments/{prod}/secret/rollback", headers=onlyb, json={"name": "K", "path": "/b", "version": 2})
    v = await client.get(f"/api/environments/{prod}/secret/version", headers=onlyb, params={"name": "K", "path": "/b", "version": 3})
    assert r3.status_code == 403, r3.text
    assert v.status_code == 200 and v.json()["value"] == "a2"


# --- 3. счетчики сходятся со списком ключей


async def test_counts_match_list(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    leaf = await _child(client, owner_headers, pid, "leaf", prod)
    for name in ("A", "B", "E", "F", "I1", "I2", "I3"):
        await _put(client, owner_headers, prod, name, "v1")
    await _put(client, owner_headers, prod, "F", "v2")
    await _put(client, owner_headers, prod, "G", "g", path="/private")
    await _delete(client, owner_headers, prod, "B")
    # дочернее: переопределение, сокрытие, возврат к наследованию, свой
    await _put(client, owner_headers, leaf, "I1", "over")
    await _put(client, owner_headers, leaf, "I2", "x")
    await _delete(client, owner_headers, leaf, "I2")
    await _put(client, owner_headers, leaf, "I3", "x")
    r = await client.post(f"/api/environments/{leaf}/secret/inherit", headers=owner_headers, json={"name": "I3", "path": "/"})
    assert r.status_code == 200, r.text
    await _put(client, owner_headers, leaf, "L", "own")
    res = await client.patch(f"/api/projects/{pid}", headers=owner_headers, json={"approval_min_level": 30})
    assert res.status_code == 200, res.text
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, None, "/", ["list", "read", "write"], project=pid)
    await _pol(client, owner_headers, uid, None, "/private", ["list", "read", "write"], allow=False, project=pid)
    dev = await login(client, "dev", PASS)
    for name in ("C", "D", "H"):
        out = await _put(client, dev, prod, name, "proposed")
        assert out.get("pending"), out
    await _put(client, dev, prod, "E", "proposed")
    r = await client.post(f"/api/environments/{prod}/secret/rollback", headers=dev, json={"name": "F", "path": "/", "version": 1})
    assert r.status_code == 200, r.text
    pend = {p["name"]: p["version"] for p in (await client.get(f"/api/environments/{prod}/pending", headers=owner_headers)).json()}
    r = await client.post(f"/api/environments/{prod}/secret/reject", headers=owner_headers, json={"name": "C", "path": "/", "version": pend["C"], "note": "no"})
    assert r.status_code == 204, r.text
    r = await client.post(f"/api/environments/{prod}/secret/approve", headers=owner_headers, json={"name": "H", "path": "/", "version": pend["H"]})
    assert r.status_code == 200, r.text
    # pending новый ключ в закрытой папке от владельца-предлагающего нельзя; добавим pending в /private от второго разработчика
    uid2 = await _user(client, owner_headers, "dev2", "developer")
    await _pol(client, owner_headers, uid2, None, "/", ["list", "read", "write"], project=pid)
    dev2 = await login(client, "dev2", PASS)
    out = await _put(client, dev2, prod, "G", "proposed-private", path="/private")
    assert out.get("pending"), out

    for who, h in (("owner", owner_headers), ("dev", dev)):
        envrows = {e["id"]: e for e in (await client.get(f"/api/projects/{pid}/environments", headers=h)).json()}
        for env in (prod, leaf):
            rows = (await client.get(f"/api/environments/{env}/secrets", headers=h)).json()
            own = [s["name"] for s in rows if not s["inherited_from"]]
            e = envrows[env]
            assert (e["secret_count"], e["own_count"]) == (len(rows), len(own))
        proj = next(p for p in (await client.get("/api/projects", headers=h)).json() if p["id"] == pid)
        assert proj["secret_count"] == sum(e["own_count"] for e in envrows.values())


# --- 5. pending_count главной считает правки в закрытой папке


async def test_pending_count_closed_folder(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "A", "v")
    res = await client.patch(f"/api/projects/{pid}", headers=owner_headers, json={"approval_min_level": 30})
    assert res.status_code == 200, res.text
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"], allow=False)
    uid2 = await _user(client, owner_headers, "dev2", "developer")
    await _pol(client, owner_headers, uid2, prod, "/", ["list", "read", "write"])
    dev2 = await login(client, "dev2", PASS)
    for i in range(3):
        out = await _put(client, dev2, prod, f"SECRET_{i}", "p", path="/private")
        assert out.get("pending"), out
    dev = await login(client, "dev", PASS)
    proj = next(p for p in (await client.get("/api/projects", headers=dev)).json() if p["id"] == pid)
    pending_list = (await client.get(f"/api/environments/{prod}/pending", headers=dev)).json()
    assert proj["pending_count"] == len(pending_list)
