"""Восьмой проход, второй круг: находки ревью исправлений первого круга.

Тесты взяты из разбора как есть и падают на коде до исправления.
"""

import time

import httpx
from sqlalchemy import event

from app import totp
from tests.conftest import login

PASS = "review9-user-2026"


async def _user(client, owner, name, role):
    res = await client.post("/api/users", headers=owner, json={"username": name, "password": PASS, "role": role})
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _pol(client, owner, sid, env, path, actions, allow=True, subject="user", project=None, require_2fa=False):
    body = {
        "subject_type": subject,
        "subject_id": sid,
        "path_prefix": path,
        "actions": actions,
        "effect": "allow" if allow else "deny",
        "require_2fa": require_2fa,
    }
    if env is not None:
        body["environment_id"] = env
    if project is not None:
        body["project_id"] = project
    res = await client.post("/api/policies", headers=owner, json=body)
    assert res.status_code == 201, res.text


async def _put(client, headers, env, name, value, path="/"):
    res = await client.put(
        f"/api/environments/{env}/secrets", headers=headers, json={"name": name, "value": value, "path": path}
    )
    assert res.status_code == 200, res.text
    return res.json()


async def _value(client, headers, env, name, path="/"):
    res = await client.get(f"/api/environments/{env}/secret", headers=headers, params={"name": name, "path": path})
    return res.json().get("value") if res.status_code == 200 else res.status_code


async def _project(client, owner, slug="shop", envs=("dev", "prod")):
    res = await client.post("/api/projects", headers=owner, json={"slug": slug, "environments": list(envs)})
    assert res.status_code == 201, res.text
    pid = res.json()["id"]
    ids = {e["name"]: e["id"] for e in (await client.get(f"/api/projects/{pid}/environments", headers=owner)).json()}
    return pid, ids


async def _child(client, owner, pid, name, parent):
    res = await client.post(f"/api/projects/{pid}/environments", headers=owner, json={"name": name, "parent_id": parent})
    assert res.status_code == 201, res.text
    return res.json()["id"]


# --- 1. счетчик проекта у не-владельца считает унаследованное второй раз ---


async def test_project_count_inherited_twice(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("dev",))
    await _child(client, owner_headers, pid, "leaf", envs["dev"])
    for name in ("A", "B", "C"):
        await _put(client, owner_headers, envs["dev"], name, "v")
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, None, "/", ["list", "read"], project=pid)
    dev = await login(client, "dev", PASS)
    owner_count = next(p for p in (await client.get("/api/projects", headers=owner_headers)).json() if p["id"] == pid)[
        "secret_count"
    ]
    dev_count = next(p for p in (await client.get("/api/projects", headers=dev)).json() if p["id"] == pid)["secret_count"]
    print("owner", owner_count, "dev", dev_count)
    assert owner_count == 3
    assert dev_count == 3, f"разработчик с полным доступом видит {dev_count}, владелец {owner_count}"


# --- 2. own_count не-владельца не считает ожидающий подтверждения новый ключ ---


async def test_own_count_pending_new_key(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "A", "v")
    res = await client.patch(f"/api/projects/{pid}", headers=owner_headers, json={"approval_min_level": 30})
    assert res.status_code == 200, res.text
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read", "write"])
    dev = await login(client, "dev", PASS)
    out = await _put(client, dev, prod, "NEW", "proposed")
    assert out.get("pending"), out
    keys = [s["name"] for s in (await client.get(f"/api/environments/{prod}/secrets", headers=dev)).json()]
    o = next(e for e in (await client.get(f"/api/projects/{pid}/environments", headers=owner_headers)).json() if e["id"] == prod)
    d = next(e for e in (await client.get(f"/api/projects/{pid}/environments", headers=dev)).json() if e["id"] == prod)
    print()
    print("keys for dev", keys, "owner", o, "dev", d)
    assert (o["own_count"], o["secret_count"]) == (d["own_count"], d["secret_count"]), (o, d)


# --- 3. переименование с неканоническим путем: прежнее место в ленте ------


async def test_rename_raw_path_leaks_old_name(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "SECRET_PAYMENT_KEY", "x", path="/private")
    res = await client.post(
        f"/api/environments/{prod}/secret/rename",
        headers=owner_headers,
        json={"path": "private", "name": "SECRET_PAYMENT_KEY", "new_path": "/", "new_name": "OLD"},
    )
    assert res.status_code == 200, res.text
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"], allow=False)
    dev = await login(client, "dev", PASS)
    events = await client.get(f"/api/environments/{prod}/events", headers=dev)
    history = await client.get(f"/api/environments/{prod}/secret/history", headers=dev, params={"name": "OLD"})
    print(events.json())
    assert "SECRET_PAYMENT_KEY" not in history.text
    assert "SECRET_PAYMENT_KEY" not in events.text, events.text


# --- 4. снимок, где ключ брался у родителя, а у родителя его больше нет ---


async def test_restore_inherits_item_parent_gone(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("dev",))
    base = envs["dev"]
    leaf = await _child(client, owner_headers, pid, "leaf", base)
    await _put(client, owner_headers, base, "X", "base")
    await _put(client, owner_headers, leaf, "X", "own")
    res = await client.post(f"/api/environments/{leaf}/secret/inherit", headers=owner_headers, json={"name": "X", "path": "/"})
    assert res.status_code == 200, res.text
    snap = await client.post(f"/api/environments/{leaf}/snapshots", headers=owner_headers, json={"name": "s0"})
    assert snap.status_code == 201, snap.text
    sid = snap.json()["id"]
    res = await client.delete(f"/api/environments/{base}/secret", headers=owner_headers, params={"name": "X"})
    assert res.status_code == 204, res.text
    await _put(client, owner_headers, leaf, "X", "again")
    # Пишет, но удалять не может.
    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, leaf, "/", ["list", "read", "write"])
    writer = await login(client, "writer", PASS)
    plan = (await client.get(f"/api/environments/{leaf}/snapshots/{sid}/plan", headers=writer)).json()
    print("plan", plan)
    restore = await client.post(f"/api/environments/{leaf}/snapshots/{sid}/restore", headers=writer)
    print("restore", restore.status_code, restore.text)
    after = await _value(client, owner_headers, leaf, "X")
    print("after", after)
    assert {row["name"]: row["action"] for row in plan}["X"] != "вернуть к наследованию"
    assert restore.status_code == 403 or after == "again", (restore.text, after)


# --- 5. сброс пароля: одинаковая политика с require_2fa у обоих -----------


async def test_reset_same_2fa_policy_both_without_2fa(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    group = (await client.post("/api/groups", headers=owner_headers, json={"name": "team"})).json()["id"]
    lead_id = await _user(client, owner_headers, "lead", "maintainer")
    dev_id = await _user(client, owner_headers, "dev", "developer")
    for uid in (lead_id, dev_id):
        r = await client.post(f"/api/groups/{group}/members", headers=owner_headers, json={"user_id": uid})
        assert r.status_code == 204
    await _pol(client, owner_headers, group, prod, "/", ["list", "read", "write"], subject="group", require_2fa=True)
    lead = await login(client, "lead", PASS)
    reset = await client.post(f"/api/users/{dev_id}/password", headers=lead, json={"new_password": "lead-knows-it-2026"})
    # Лиду достаточно включить второй фактор себе - и права те же.
    start = await client.post("/api/auth/2fa/start", headers=lead)
    secret = start.json()["secret"]
    code = totp._code(secret, totp.counter_now(time.time()))
    enabled = await client.post("/api/auth/2fa/enable", headers=lead, json={"password": PASS, "code": code})
    assert enabled.status_code == 200, enabled.text
    relog = await client.post("/api/auth/login", json={"username": "lead", "password": PASS, "otp": totp._code(secret, totp.counter_now(time.time()) + 1)})
    lead = {"Authorization": f"Bearer {relog.json()['access_token']}"}
    reset2 = await client.post(f"/api/users/{dev_id}/password", headers=lead, json={"new_password": "lead-knows-it-2026"})
    # Без второго фактора у самого актора - отказ (сброс не спрашивает его
    # пароль, и чужая сессия не должна открывать права "только с 2FA"); со
    # вторым фактором - можно.
    assert reset.status_code == 403, reset.text
    assert reset2.status_code == 204, reset2.text


# --- 6. число запросов главной для не-владельца --------------------------


async def test_own_count_child_hide_override_inherit(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("dev",))
    base = envs["dev"]
    mid = await _child(client, owner_headers, pid, "mid", base)
    leaf = await _child(client, owner_headers, pid, "leaf", mid)
    for name in ("A", "B", "C", "D"):
        await _put(client, owner_headers, base, name, "v")
    await _put(client, owner_headers, leaf, "A", "over")          # переопределение
    await _put(client, owner_headers, leaf, "B", "tmp")
    r = await client.delete(f"/api/environments/{leaf}/secret", headers=owner_headers, params={"name": "B"})
    assert r.status_code == 204, r.text                            # сокрытие удалением
    await _put(client, owner_headers, leaf, "C", "over")
    r = await client.post(f"/api/environments/{leaf}/secret/inherit", headers=owner_headers, json={"name": "C", "path": "/"})
    assert r.status_code == 200, r.text                            # снова наследует
    await _put(client, owner_headers, leaf, "OWN", "x")
    await _put(client, owner_headers, mid, "D", "tmp")
    r = await client.delete(f"/api/environments/{mid}/secret", headers=owner_headers, params={"name": "D"})
    assert r.status_code == 204, r.text                            # скрыт у середины
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, None, "/", ["list", "read"], project=pid)
    dev = await login(client, "dev", PASS)
    o = {e["name"]: (e["secret_count"], e["own_count"]) for e in (await client.get(f"/api/projects/{pid}/environments", headers=owner_headers)).json()}
    d = {e["name"]: (e["secret_count"], e["own_count"]) for e in (await client.get(f"/api/projects/{pid}/environments", headers=dev)).json()}
    print()
    print("owner", o, "dev", d)
    assert o == d


async def test_inherit_gone_three_levels(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _project(client, owner_headers, envs=("dev",))
    root = envs["dev"]
    mid = await _child(client, owner_headers, pid, "mid", root)
    leaf = await _child(client, owner_headers, pid, "leaf", mid)
    await _put(client, owner_headers, root, "K1", "root")
    await _put(client, owner_headers, mid, "K1", "tmp")
    assert (await client.delete(f"/api/environments/{mid}/secret", headers=owner_headers, params={"name": "K1"})).status_code == 204
    await _put(client, owner_headers, root, "K2", "root")
    await _put(client, owner_headers, mid, "K2", "mid")
    await _put(client, owner_headers, root, "K3", "root")
    sid = (await client.post(f"/api/environments/{leaf}/snapshots", headers=owner_headers, json={"name": "s0"})).json()["id"]
    assert (await client.delete(f"/api/environments/{root}/secret", headers=owner_headers, params={"name": "K2"})).status_code == 204
    for name in ("K1", "K2", "K3", "K4"):
        await _put(client, owner_headers, leaf, name, "leaf")
    await _put(client, owner_headers, leaf, "K5", "leaf", path="/a")
    plan = {r["name"]: r["action"] for r in (await client.get(f"/api/environments/{leaf}/snapshots/{sid}/plan", headers=owner_headers)).json()}
    print()
    print("plan", plan)
    # Только удаление в /a.
    uid = await _user(client, owner_headers, "w", "developer")
    await _pol(client, owner_headers, uid, leaf, "/", ["list", "read", "write"])
    await _pol(client, owner_headers, uid, leaf, "/a", ["delete"])
    w = await login(client, "w", PASS)
    res = await client.post(f"/api/environments/{leaf}/snapshots/{sid}/restore", headers=w)
    print("partial delete restore", res.status_code, res.text)
    res = await client.post(f"/api/environments/{leaf}/snapshots/{sid}/restore", headers=owner_headers)
    print("owner restore", res.status_code, res.text)
    vals = {n: await _value(client, owner_headers, leaf, n) for n in ("K1", "K2", "K3", "K4")}
    vals["K5"] = await _value(client, owner_headers, leaf, "K5", path="/a")
    print("after", vals)
    assert plan["K1"].startswith("убрать") and plan["K4"].startswith("убрать") and plan["K5"].startswith("убрать")
    assert plan["K2"] == plan["K3"] == "вернуть к наследованию"
    assert vals == {"K1": 404, "K2": "mid", "K3": "root", "K4": 404, "K5": 404}


async def test_old_value_from_closed_folder_readable(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _project(client, owner_headers, envs=("prod",))
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "PAY", "old-private-value", path="/private")
    await _put(client, owner_headers, prod, "PAY", "new-private-value", path="/private")
    r = await client.post(f"/api/environments/{prod}/secret/rename", headers=owner_headers,
                          json={"path": "/private", "name": "PAY", "new_path": "/", "new_name": "PUB"})
    assert r.status_code == 200, r.text
    await _put(client, owner_headers, prod, "PUB", "public-now")
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"], allow=False)
    dev = await login(client, "dev", PASS)
    hist = (await client.get(f"/api/environments/{prod}/secret/history", headers=dev, params={"name": "PUB"})).json()
    v1 = await client.get(f"/api/environments/{prod}/secret/version", headers=dev, params={"name": "PUB", "version": 1})
    assert v1.status_code == 403, v1.text
    assert "old-private-value" not in v1.text
    assert "/private" not in str(hist)
    # Версии, записанные в закрытой папке, помечены: интерфейс их не раскрывает.
    assert hist[-1]["closed"] is True and hist[0]["closed"] is False
    # Последняя версия, записанная уже в корне, читается.
    last = hist[0]["version"]
    current = await client.get(f"/api/environments/{prod}/secret/version", headers=dev, params={"name": "PUB", "version": last})
    assert current.status_code == 200 and current.json()["value"] == "public-now"
    # И откатиться на значение закрытой папки нельзя.
    uid2 = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid2, prod, "/", ["list", "read", "write"])
    await _pol(client, owner_headers, uid2, prod, "/private", ["list", "read"], allow=False)
    writer = await login(client, "writer", PASS)
    back = await client.post(
        f"/api/environments/{prod}/secret/rollback", headers=writer, json={"name": "PUB", "path": "/", "version": 1}
    )
    assert back.status_code == 403, back.text


async def test_projects_list_queries_do_not_grow_with_environments(client: httpx.AsyncClient, owner_headers, unsealed):
    """Счетчики не-владельца - постоянным числом запросов: раньше на каждое
    окружение шли свои, и главная на сотне окружений делала сотни запросов."""
    uid = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, uid, None, "/", ["list", "read"])
    dev = await login(client, "dev", PASS)
    app = client._transport.app
    counter = {"n": 0}

    def on_exec(*_args, **_kw):
        counter["n"] += 1

    async def add(first, last):
        for i in range(first, last):
            pid, envs = await _project(client, owner_headers, slug=f"p{i}", envs=("dev", "stage", "prod"))
            await _child(client, owner_headers, pid, "leaf", envs["dev"])
            await _put(client, owner_headers, envs["dev"], "A", "v")

    async def measure():
        event.listen(app.state.engine.sync_engine, "before_cursor_execute", on_exec)
        try:
            counter["n"] = 0
            res = await client.get("/api/projects", headers=dev)
            assert res.status_code == 200
            return counter["n"]
        finally:
            event.remove(app.state.engine.sync_engine, "before_cursor_execute", on_exec)

    await add(0, 2)
    few = await measure()
    await add(2, 10)
    assert await measure() == few
