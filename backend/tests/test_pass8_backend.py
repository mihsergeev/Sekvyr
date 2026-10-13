"""Находки восьмого прохода: ревью правок седьмого.

Каждый тест воспроизводит сценарий из разбора и падает на коде до исправления.
"""

import time

import httpx

from app import totp
from tests.conftest import login

PASS = "pass8-user-2026"


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


async def _value(client, headers, env, name, path="/"):
    res = await client.get(f"/api/environments/{env}/secret", headers=headers, params={"name": name, "path": path})
    return res.json().get("value") if res.status_code == 200 else res.status_code


async def _setup(client, owner):
    res = await client.post("/api/projects", headers=owner, json={"slug": "shop", "environments": ["dev", "prod"]})
    assert res.status_code == 201, res.text
    pid = res.json()["id"]
    envs = {e["name"]: e["id"] for e in (await client.get(f"/api/projects/{pid}/environments", headers=owner)).json()}
    await _put(client, owner, envs["prod"], "APP", "app-value")
    await _put(client, owner, envs["prod"], "SECRET_PAYMENT_KEY", "top-secret-value-0001", path="/private")
    await _put(client, owner, envs["prod"], "TOKEN", "changeme", path="/private")
    return pid, envs


async def _denied(client, owner, envs):
    uid = await _user(client, owner, "dev", "developer")
    await _pol(client, owner, uid, envs["prod"], "/", ["list", "read"])
    await _pol(client, owner, uid, envs["prod"], "/private", ["list", "read"], allow=False)
    return uid, await login(client, "dev", PASS)


# --- охват прав при сбросе пароля -------------------------------------------


async def test_reset_counts_rights_that_wait_for_2fa(client: httpx.AsyncClient, owner_headers, unsealed):
    """Право на prod с require_2fa у цели без второго фактора - тоже ее право:
    со своим паролем фактор включают за минуту."""
    _pid, envs = await _setup(client, owner_headers)
    lead_id = await _user(client, owner_headers, "lead", "maintainer")
    await _pol(client, owner_headers, lead_id, envs["dev"], "/", ["list", "read", "write"])
    lead = await login(client, "lead", PASS)
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, dev_id, envs["prod"], "/", ["list", "read"], require_2fa=True)

    reset = await client.post(f"/api/users/{dev_id}/password", headers=lead, json={"new_password": "lead-knows-it-2026"})
    assert reset.status_code == 403, reset.text

    # Для полноты: тот самый путь, который сброс открывал бы.
    as_dev = await login(client, "dev", PASS)
    start = await client.post("/api/auth/2fa/start", headers=as_dev)
    secret = start.json()["secret"]
    code = totp._code(secret, totp.counter_now(time.time()))
    enabled = await client.post("/api/auth/2fa/enable", headers=as_dev, json={"password": PASS, "code": code})
    assert enabled.status_code == 200, enabled.text


async def test_reset_counts_rights_a_promotion_would_open(client: httpx.AsyncClient, owner_headers, unsealed):
    """Запись наблюдателю не действует, пока он наблюдатель, но повысить его
    ответственный может сам - значит, это тоже права цели."""
    _pid, envs = await _setup(client, owner_headers)
    lead_id = await _user(client, owner_headers, "lead", "maintainer")
    await _pol(client, owner_headers, lead_id, envs["prod"], "/", ["list", "read"])
    lead = await login(client, "lead", PASS)
    viewer_id = await _user(client, owner_headers, "watcher", "viewer")
    # Наблюдателю запись лично не выдать, а через группу она приходит.
    group = (await client.post("/api/groups", headers=owner_headers, json={"name": "backend"})).json()["id"]
    added = await client.post(f"/api/groups/{group}/members", headers=owner_headers, json={"user_id": viewer_id})
    assert added.status_code == 204, added.text
    await _pol(client, owner_headers, group, envs["prod"], "/", ["list", "read", "write"], subject="group")

    reset = await client.post(
        f"/api/users/{viewer_id}/password", headers=lead, json={"new_password": "lead-knows-it-2026"}
    )
    assert reset.status_code == 403, reset.text


async def test_reset_still_works_within_cover(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    lead_id = await _user(client, owner_headers, "lead", "maintainer")
    await _pol(client, owner_headers, lead_id, envs["dev"], "/", ["list", "read", "write"])
    lead = await login(client, "lead", PASS)
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _pol(client, owner_headers, dev_id, envs["dev"], "/", ["list", "read"], require_2fa=True)
    reset = await client.post(f"/api/users/{dev_id}/password", headers=lead, json={"new_password": "lead-knows-it-2026"})
    assert reset.status_code == 204, reset.text


# --- наследник и копия - только от читаемого целиком -----------------------


async def test_copy_and_parent_check_policy_folders_too(client: httpx.AsyncClient, owner_headers, unsealed):
    """Запрет на пустую пока папку: ключ, положенный туда потом, наследник
    отдавал бы тому, кто сам его не читает."""
    pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    lead_id = await _user(client, owner_headers, "lead", "maintainer")
    await _pol(client, owner_headers, lead_id, None, "/", ["list", "read", "write"], project=pid)
    await _pol(client, owner_headers, lead_id, prod, "/vault", ["list", "read"], allow=False)
    lead = await login(client, "lead", PASS)
    child = await client.post(f"/api/projects/{pid}/environments", headers=lead, json={"name": "child", "parent_id": prod})
    assert child.status_code == 403, child.text
    copy = await client.post(f"/api/projects/{pid}/environments", headers=lead, json={"name": "copy", "copy_from": prod})
    assert copy.status_code == 403, copy.text
    # Без запрета то же самое можно: отказ - именно из-за папки.
    plain = await client.post(f"/api/projects/{pid}/environments", headers=lead, json={"name": "child2", "parent_id": envs["dev"]})
    assert plain.status_code == 201, plain.text


async def test_env_create_in_hidden_project(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, _envs = await _setup(client, owner_headers)
    lead_id = await _user(client, owner_headers, "lead", "maintainer")
    await _pol(client, owner_headers, lead_id, None, "/", ["list", "read", "write"])
    await _pol(client, owner_headers, lead_id, None, "/", ["list", "read"], allow=False, project=pid)
    lead = await login(client, "lead", PASS)
    assert "shop" not in [p["slug"] for p in (await client.get("/api/projects", headers=lead)).json()]
    for name in ("prod", "nosuch"):
        res = await client.post(f"/api/projects/{pid}/environments", headers=lead, json={"name": name})
        assert res.status_code == 404, res.text


# --- снимки ----------------------------------------------------------------


async def test_restore_needs_delete_to_remove_keys(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read", "write"])
    writer = await login(client, "writer", PASS)
    snap = await client.post(f"/api/environments/{prod}/snapshots", headers=writer, json={"name": "s0"})
    assert snap.status_code == 201, snap.text
    await _put(client, owner_headers, prod, "NEW_BY_OWNER", "v")
    restore = await client.post(f"/api/environments/{prod}/snapshots/{snap.json()['id']}/restore", headers=writer)
    assert restore.status_code == 403, restore.text
    assert await _value(client, owner_headers, prod, "NEW_BY_OWNER") == "v"


async def test_restore_in_child_says_a_key_will_go(client: httpx.AsyncClient, owner_headers, unsealed):
    """Ключ наследника, которого у родителя нет: "вернуть к наследованию" на
    деле его убирает, и план с итогом должны так и сказать."""
    pid, envs = await _setup(client, owner_headers)
    base = envs["dev"]
    child = (
        await client.post(f"/api/projects/{pid}/environments", headers=owner_headers, json={"name": "leaf", "parent_id": base})
    ).json()["id"]
    await _put(client, owner_headers, base, "K", "base")
    snap = (await client.post(f"/api/environments/{child}/snapshots", headers=owner_headers, json={"name": "s0"})).json()["id"]
    await _put(client, owner_headers, child, "K", "own")
    await _put(client, owner_headers, child, "NEW", "n")
    plan = (await client.get(f"/api/environments/{child}/snapshots/{snap}/plan", headers=owner_headers)).json()
    actions = {row["name"]: row["action"] for row in plan}
    assert actions["K"] == "вернуть к наследованию"
    assert actions["NEW"].startswith("убрать")
    res = await client.post(f"/api/environments/{child}/snapshots/{snap}/restore", headers=owner_headers)
    assert res.json() == {"restored": 1, "removed": 1}
    assert await _value(client, owner_headers, child, "K") == "base"
    assert await _value(client, owner_headers, child, "NEW") == 404


# --- имена из закрытой папки ------------------------------------------------


async def test_mutes_hide_closed_folders(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    res = await client.post(
        f"/api/environments/{prod}/lint/mute", headers=owner_headers, json={"path": "/private", "name": "TOKEN", "code": "placeholder"}
    )
    assert res.status_code == 204, res.text
    _uid, dev = await _denied(client, owner_headers, envs)
    mutes = await client.get(f"/api/environments/{prod}/lint/mutes", headers=dev)
    assert mutes.status_code == 200 and mutes.json() == []


async def test_rename_out_of_closed_folder_hides_old_place(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    res = await client.post(
        f"/api/environments/{prod}/secret/rename",
        headers=owner_headers,
        json={"path": "/private", "name": "SECRET_PAYMENT_KEY", "new_path": "/", "new_name": "OLD"},
    )
    assert res.status_code == 200, res.text
    _uid, dev = await _denied(client, owner_headers, envs)
    events = await client.get(f"/api/environments/{prod}/events", headers=dev)
    history = await client.get(f"/api/environments/{prod}/secret/history", headers=dev, params={"name": "OLD"})
    assert events.status_code == history.status_code == 200
    assert "SECRET_PAYMENT_KEY" not in events.text and "/private" not in events.text
    assert "SECRET_PAYMENT_KEY" not in history.text and "/private" not in history.text
    # Владелец видит все как было.
    own = await client.get(f"/api/environments/{prod}/secret/history", headers=owner_headers, params={"name": "OLD"})
    assert "SECRET_PAYMENT_KEY" in own.text


async def test_counts_skip_closed_folders(client: httpx.AsyncClient, owner_headers, unsealed):
    pid, envs = await _setup(client, owner_headers)
    _uid, dev = await _denied(client, owner_headers, envs)
    project = next(p for p in (await client.get("/api/projects", headers=dev)).json() if p["id"] == pid)
    assert project["secret_count"] == 1
    env = next(e for e in (await client.get(f"/api/projects/{pid}/environments", headers=dev)).json() if e["name"] == "prod")
    assert env["secret_count"] == 1 and env["own_count"] == 1


# --- машина с правом на одну папку -----------------------------------------


async def test_folder_only_machine_app_is_remembered(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    await _put(client, owner_headers, prod, "PORT", "8080", path="/app")
    made = (await client.post("/api/machines", headers=owner_headers, json={"name": "node"})).json()
    await _pol(client, owner_headers, made["id"], prod, "/app", ["list", "read"], subject="machine")
    token = (
        await client.post(
            "/api/v1/machine/token", json={"client_id": made["client_id"], "client_secret": made["client_secret"]}
        )
    ).json()["access_token"]
    head = {"Authorization": f"Bearer {token}"}
    rep = await client.post(
        "/api/v1/machine/report",
        headers=head,
        json={"agent_version": "1.0.0", "applied": "keys 1", "project": "shop", "env": "prod", "path": "/srv/.env"},
    )
    assert rep.status_code == 200, rep.text
    card = next(m for m in (await client.get("/api/machines", headers=owner_headers)).json() if m["id"] == made["id"])
    assert card["apps"], card
