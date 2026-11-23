"""Права по папкам: запрет на папку действует везде, а не только в чтении ключа.

Седьмой проход проверки нашел, что запрет на /private соблюдался в
GET /secret и обходился всем, что работает с окружением целиком: выгрузкой,
"всеми значениями", выгрузкой проекта, замечаниями, сравнением и "где еще
такое же значение" (оракул угадывания), снимками, машиной (своей подключенной
и с собственной политикой), сбросом пароля и переименованием "везде".
"""

import asyncio

import httpx

from tests.conftest import login

PASS = "folder-pass-2026"
SECRET = "top-secret-value-0001"


async def _user(client, owner, name, role):
    res = await client.post(
        "/api/users", headers=owner, json={"username": name, "password": PASS, "role": role}
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _pol(client, owner, sid, env, path, actions, allow=True, subject="user"):
    res = await client.post(
        "/api/policies",
        headers=owner,
        json={
            "subject_type": subject,
            "subject_id": sid,
            "environment_id": env,
            "path_prefix": path,
            "actions": actions,
            "effect": "allow" if allow else "deny",
        },
    )
    assert res.status_code == 201, res.text


async def _put(client, headers, env, name, value, path="/"):
    res = await client.put(
        f"/api/environments/{env}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )
    assert res.status_code == 200, res.text


async def _setup(client, owner):
    res = await client.post(
        "/api/projects", headers=owner, json={"slug": "shop", "environments": ["dev", "prod"]}
    )
    assert res.status_code == 201, res.text
    pid = res.json()["id"]
    envs = {
        e["name"]: e["id"]
        for e in (await client.get(f"/api/projects/{pid}/environments", headers=owner)).json()
    }
    await _put(client, owner, envs["prod"], "APP", "app-value")
    await _put(client, owner, envs["prod"], "SECRET", SECRET, path="/private")
    await _put(client, owner, envs["prod"], "TOKEN", "changeme", path="/private")
    return pid, envs


async def _denied_reader(client, owner, envs, name="dev", role="developer"):
    uid = await _user(client, owner, name, role)
    await _pol(client, owner, uid, envs["prod"], "/", ["list", "read"])
    await _pol(client, owner, uid, envs["prod"], "/private", ["list", "read"], allow=False)
    await _pol(client, owner, uid, envs["dev"], "/", ["list", "read", "write"])
    return uid, await login(client, name, PASS)


async def test_whole_environment_reads_respect_folder_deny(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    pid, envs = await _setup(client, owner_headers)
    _uid, dev = await _denied_reader(client, owner_headers, envs)
    prod = envs["prod"]

    baseline = await client.get(
        f"/api/environments/{prod}/secret", headers=dev, params={"name": "SECRET", "path": "/private"}
    )
    assert baseline.status_code == 403

    for route in ("values", "export"):
        res = await client.get(f"/api/environments/{prod}/{route}", headers=dev)
        assert res.status_code == 403, (route, res.text)
        assert SECRET not in res.text

    project = await client.get(f"/api/projects/{pid}/export", headers=dev)
    assert SECRET not in project.text
    if project.status_code == 200:
        assert "prod" in project.json()["skipped"]

    lint = await client.get(f"/api/environments/{prod}/lint", headers=dev)
    assert lint.status_code == 200, lint.text
    assert not [n for n in lint.json() if n["path"] == "/private"]

    names = await client.get(f"/api/environments/{prod}/secrets", headers=dev)
    assert names.status_code == 200
    assert {(r["path"], r["name"]) for r in names.json()} == {("/", "APP")}


async def test_same_and_diff_are_not_oracles(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    _uid, dev = await _denied_reader(client, owner_headers, envs)

    await _put(client, dev, envs["dev"], "GUESS", SECRET)
    same = await client.get(
        f"/api/environments/{envs['dev']}/same", headers=dev, params={"name": "GUESS"}
    )
    assert same.status_code == 200, same.text
    assert not [r for r in same.json() if r["path"] == "/private"]

    await _put(client, dev, envs["dev"], "SECRET", SECRET, path="/private")
    diff = await client.get(
        f"/api/environments/{envs['dev']}/diff", headers=dev, params={"other": envs["prod"]}
    )
    assert diff.status_code == 200, diff.text
    body = diff.json()
    # Ключ из закрытой папки прода не виден вовсе, значит и "совпадает" о нем
    # сказать нельзя.
    assert body["same"] == 0
    assert not [r for r in body["rows"] if r["path"] == "/private" and r["state"] != "here"]


async def test_parent_change_needs_every_folder(client: httpx.AsyncClient, owner_headers, unsealed):
    """Новый родитель приносит ключи и в папку, где менять запрещено."""
    _pid, envs = await _setup(client, owner_headers)
    await _put(client, owner_headers, envs["dev"], "EXTRA", "from-dev", path="/private")
    uid = await _user(client, owner_headers, "keeper", "maintainer")
    await _pol(client, owner_headers, uid, envs["dev"], "/", ["list", "read", "write"])
    await _pol(client, owner_headers, uid, envs["prod"], "/", ["list", "read", "write"])
    await _pol(client, owner_headers, uid, envs["prod"], "/private", ["write"], allow=False)
    keeper = await login(client, "keeper", PASS)
    res = await client.patch(
        f"/api/environments/{envs['prod']}", headers=keeper, json={"parent_id": envs["dev"]}
    )
    assert res.status_code == 403, res.text
    listed = await client.get(f"/api/environments/{envs['prod']}/secrets", headers=owner_headers)
    assert "EXTRA" not in {row["name"] for row in listed.json()}


async def test_environment_patch_respects_folder_and_parent_visibility(client, owner_headers, unsealed):
    pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    assert (await client.patch(
        f"/api/environments/{prod}", headers=owner_headers, json={"parent_id": envs["dev"]}
    )).status_code == 200
    uid = await _user(client, owner_headers, "keeper", "maintainer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "write"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list"], allow=False)
    keeper = await login(client, "keeper", PASS)

    edited = await client.patch(
        f"/api/environments/{prod}", headers=keeper, json={"title": "Production"}
    )
    assert edited.status_code == 200, edited.text
    listed = await client.get(f"/api/projects/{pid}/environments", headers=keeper)
    assert listed.status_code == 200, listed.text
    for row in (edited.json(), listed.json()[0]):
        assert row["title"] == "Production"
        assert row["parent_id"] is None
        assert row["parent_name"] == ""
        assert row["secret_count"] == row["own_count"] == 1
    owner = await client.get(f"/api/projects/{pid}/environments", headers=owner_headers)
    owner_prod = next(row for row in owner.json() if row["id"] == prod)
    assert owner_prod["parent_id"] == envs["dev"]
    assert owner_prod["secret_count"] == 3


async def test_snapshot_counts_use_the_saved_folder_visibility(client, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    base = f"/api/environments/{envs['prod']}"
    uid, dev = await _denied_reader(client, owner_headers, envs)
    await _pol(client, owner_headers, uid, envs["prod"], "/", ["write"])
    created = await client.post(f"{base}/snapshots", headers=dev, json={"name": "before"})
    assert created.status_code == 201, created.text
    assert created.json()["keys"] == 1
    renamed = await client.post(f"{base}/secret/rename", headers=owner_headers, json={
        "path": "/private", "name": "SECRET", "new_path": "/", "new_name": "PUBLIC",
    })
    assert renamed.status_code == 200, renamed.text
    for headers, keys in ((dev, 1), (owner_headers, 3)):
        listed = await client.get(f"{base}/snapshots", headers=headers)
        assert listed.status_code == 200, listed.text
        assert listed.json()[0]["keys"] == keys


async def test_events_exclude_unrelated_audit_and_hidden_folder_totals(client, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    base = f"/api/environments/{prod}"
    await _user(client, owner_headers, str(prod), "developer")
    assert (await client.get(f"{base}/export", headers=owner_headers)).status_code == 200
    uid = await _user(client, owner_headers, "viewer", "viewer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read"])
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"], allow=False)
    dev = await login(client, "viewer", PASS)

    for headers in (dev, owner_headers):
        events = await client.get(f"{base}/events", headers=headers)
        assert events.status_code == 200, events.text
        rows = events.json()
        assert not any(row["action"] == "user_created" for row in rows)
        assert any(row["action"] == "secret_written" and row["key"] == "APP" for row in rows)
        exports = [row["detail"] for row in rows if row["action"] == "env_exported"]
        assert exports == ([""] if headers == dev else ["ключей: 3"])


async def test_events_keep_environment_records_without_a_key(client, owner_headers, env_id):
    from app import audit

    app = client._transport.app
    async with app.state.session_factory() as session:
        for action in ("machine_denied", "secrets_migrated"):
            await audit.record(session, actor="owner", action=action, target=str(env_id))
        await session.commit()
    events = await client.get(f"/api/environments/{env_id}/events", headers=owner_headers)
    assert events.status_code == 200, events.text
    assert {"machine_denied", "secrets_migrated"} <= {row["action"] for row in events.json()}


async def test_events_hide_ambiguous_legacy_paths_and_keep_long_owner_events(client, owner_headers, env_id):
    from app import secrets_store

    app = client._transport.app
    async with app.state.session_factory() as session:
        # Раньше в именах ключей допускалось двоеточие.
        await secrets_store.set_value(
            session, app.state.sealbox, env_id=env_id, path="/app", name="private:TOKEN",
            value="legacy", author="owner", legacy_name=True,
        )
        await session.commit()
    await _put(client, owner_headers, env_id, "TOKEN", "hidden", path="/app:private")
    base = f"/api/environments/{env_id}"
    moved = await client.post(f"{base}/secret/rename", headers=owner_headers, json={
        "path": "/app:private", "name": "TOKEN", "new_path": "/closed", "new_name": "TOKEN",
    })
    assert moved.status_code == 200, moved.text
    long_path = "/" + "a" * 199
    await _put(client, owner_headers, env_id, "LONG", "hidden", path=long_path)
    await _put(client, owner_headers, env_id, "OPEN", "visible", path="/app")
    await _put(client, owner_headers, env_id, "OPEN", "visible", path="/allowed:branch")
    uid = await _user(client, owner_headers, "viewer", "viewer")
    await _pol(client, owner_headers, uid, env_id, "/app", ["list"])
    await _pol(client, owner_headers, uid, env_id, "/allowed:branch", ["list"])
    viewer = await login(client, "viewer", PASS)

    scoped = await client.get(f"{base}/events", headers=viewer)
    assert scoped.status_code == 200, scoped.text
    assert [row["key"] for row in scoped.json()] == ["/allowed:branch/OPEN", "/app/OPEN"]
    full = await client.get(f"{base}/events", headers=owner_headers)
    assert full.status_code == 200, full.text
    assert f"{long_path}/LONG" in {row["key"] for row in full.json()}


async def test_stop_override_needs_delete_when_parent_has_no_value(client, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    parent, prod = envs["dev"], envs["prod"]
    base = f"/api/environments/{prod}"
    assert (await client.patch(f"{base}", headers=owner_headers, json={"parent_id": parent})).status_code == 200
    await _put(client, owner_headers, parent, "INHERITED", "parent-value")
    await _put(client, owner_headers, prod, "INHERITED", "own-value")
    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read", "write"])
    writer = await login(client, "writer", PASS)

    gone = await client.post(f"{base}/secret/inherit", headers=writer, json={"name": "APP"})
    assert gone.status_code == 403, gone.text
    assert (await client.get(f"{base}/secret", headers=writer, params={"name": "APP"})).json()["value"] == "app-value"
    fallback = await client.post(f"{base}/secret/inherit", headers=writer, json={"name": "INHERITED"})
    assert fallback.status_code == 200, fallback.text
    assert (await client.get(f"{base}/secret", headers=writer, params={"name": "INHERITED"})).json()["value"] == "parent-value"


async def test_stop_override_checks_parent_after_lock(client, owner_headers, unsealed, monkeypatch):
    from app.api import secrets

    pid, envs = await _setup(client, owner_headers)
    parent, prod = envs["dev"], envs["prod"]
    base = f"/api/environments/{prod}"
    made = await client.post(f"/api/projects/{pid}/environments", headers=owner_headers, json={"name": "empty"})
    assert made.status_code == 201, made.text
    assert (await client.patch(f"{base}", headers=owner_headers, json={"parent_id": parent})).status_code == 200
    await _put(client, owner_headers, parent, "APP", "parent-value")
    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, prod, "/", ["write"])
    writer = await login(client, "writer", PASS)
    checked, resume = asyncio.Event(), asyncio.Event()
    guard = secrets._guard

    async def after_guard(*args):
        env = await guard(*args)
        checked.set()
        await resume.wait()
        return env

    monkeypatch.setattr(secrets, "_guard", after_guard)
    request = asyncio.create_task(client.post(f"{base}/secret/inherit", headers=writer, json={"name": "APP"}))
    try:
        await asyncio.wait_for(checked.wait(), 5)
        changed = await client.patch(f"{base}", headers=owner_headers, json={"parent_id": made.json()["id"]})
        assert changed.status_code == 200, changed.text
    finally:
        resume.set()
    result = await request
    assert result.status_code == 403, result.text
    kept = await client.get(f"{base}/secret", headers=owner_headers, params={"name": "APP"})
    assert kept.json()["value"] == "app-value"


async def test_snapshot_restore_needs_every_folder(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    uid = await _user(client, owner_headers, "keeper", "maintainer")
    await _pol(client, owner_headers, uid, envs["prod"], "/", ["list", "read", "write", "delete"])
    await _pol(client, owner_headers, uid, envs["prod"], "/private", ["write", "delete"], allow=False)
    keeper = await login(client, "keeper", PASS)
    prod = envs["prod"]

    made = await client.post(f"/api/environments/{prod}/snapshots", headers=owner_headers, json={"name": "before"})
    assert made.status_code == 201, made.text
    await _put(client, owner_headers, prod, "SECRET", "rotated-value", path="/private")

    restore = await client.post(
        f"/api/environments/{prod}/snapshots/{made.json()['id']}/restore", headers=keeper
    )
    assert restore.status_code == 403, restore.text
    still = await client.get(
        f"/api/environments/{prod}/secret", headers=owner_headers, params={"name": "SECRET", "path": "/private"}
    )
    assert still.json()["value"] == "rotated-value"


async def test_machine_gets_only_allowed_folders(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]

    # Ответственный с запретом на /private не подключает свою машину к проду:
    # машине выдается корень, и через нее читалась бы закрытая папка.
    uid = await _user(client, owner_headers, "keeper", "maintainer")
    await _pol(client, owner_headers, uid, prod, "/", ["list", "read"])
    await _pol(client, owner_headers, uid, prod, "/private", ["read"], allow=False)
    keeper = await login(client, "keeper", PASS)
    made = await client.post("/api/machines", headers=keeper, json={"name": "box"})
    assert made.status_code == 201, made.text
    attach = await client.post(
        f"/api/machines/{made.json()['id']}/attach", headers=keeper, json={"environment_id": prod}
    )
    assert attach.status_code == 403, attach.text

    # Машина с разрешением на корень и запретом на папку: папки нет ни в
    # /secrets, ни в /env.
    box = (await client.post("/api/machines", headers=owner_headers, json={"name": "box2"})).json()
    await _pol(client, owner_headers, box["id"], prod, "/", ["list", "read"], subject="machine")
    await _pol(client, owner_headers, box["id"], prod, "/private", ["read"], allow=False, subject="machine")
    token = (
        await client.post(
            "/api/v1/machine/token", json={"client_id": box["client_id"], "client_secret": box["client_secret"]}
        )
    ).json()["access_token"]
    head = {"Authorization": f"Bearer {token}"}
    secrets = await client.get("/api/v1/machine/secrets", headers=head, params={"project": "shop", "env": "prod"})
    assert secrets.status_code == 200, secrets.text
    assert {v["name"] for v in secrets.json()["values"]} == {"APP"}
    env_file = await client.get("/api/v1/machine/env", headers=head, params={"project": "shop", "env": "prod"})
    assert env_file.status_code == 200, env_file.text
    assert SECRET not in env_file.text and "APP=" in env_file.text

    # Машина с политикой только на папку получает эту папку, а не отказ.
    only = (await client.post("/api/machines", headers=owner_headers, json={"name": "box3"})).json()
    await _pol(client, owner_headers, only["id"], prod, "/private", ["list", "read"], subject="machine")
    token = (
        await client.post(
            "/api/v1/machine/token", json={"client_id": only["client_id"], "client_secret": only["client_secret"]}
        )
    ).json()["access_token"]
    got = await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": f"Bearer {token}"},
        params={"project": "shop", "env": "prod"},
    )
    assert got.status_code == 200, got.text
    assert {v["name"] for v in got.json()["values"]} == {"SECRET", "TOKEN"}


async def test_password_reset_needs_cover_of_folders(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    keeper_id = await _user(client, owner_headers, "keeper", "maintainer")
    await _pol(client, owner_headers, keeper_id, prod, "/", ["list", "read"])
    await _pol(client, owner_headers, keeper_id, prod, "/private", ["read"], allow=False)
    victim = await _user(client, owner_headers, "victim", "developer")
    await _pol(client, owner_headers, victim, prod, "/", ["list", "read"])
    keeper = await login(client, "keeper", PASS)

    res = await client.post(
        f"/api/users/{victim}/password", headers=keeper, json={"new_password": "taken-over-2026"}
    )
    assert res.status_code == 403, res.text


async def test_rename_everywhere_does_not_take_a_closed_folder(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    _pid, envs = await _setup(client, owner_headers)
    uid = await _user(client, owner_headers, "ren", "developer")
    rw = ["list", "read", "write"]
    await _pol(client, owner_headers, uid, envs["dev"], "/", rw)
    await _pol(client, owner_headers, uid, envs["prod"], "/", rw)
    await _pol(client, owner_headers, uid, envs["prod"], "/private", rw, allow=False)
    ren = await login(client, "ren", PASS)

    await _put(client, ren, envs["dev"], "SECRET", "whatever", path="/private")
    res = await client.post(
        f"/api/environments/{envs['dev']}/secret/rename",
        headers=ren,
        json={"name": "SECRET", "path": "/private", "new_name": "SECRET", "new_path": "/app", "everywhere": True},
    )
    assert res.status_code == 200, res.text
    assert "prod" not in res.json()["also_renamed"]
    left = await client.get(
        f"/api/environments/{envs['prod']}/secret",
        headers=owner_headers,
        params={"name": "SECRET", "path": "/private"},
    )
    assert left.status_code == 200 and left.json()["value"] == SECRET


async def test_rename_from_a_write_only_folder_needs_read(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "write"])
    await _pol(client, owner_headers, uid, prod, "/app", ["list", "read", "write"])
    writer = await login(client, "writer", PASS)
    res = await client.post(
        f"/api/environments/{prod}/secret/rename",
        headers=writer,
        json={"name": "SECRET", "path": "/private", "new_name": "SECRET", "new_path": "/app"},
    )
    assert res.status_code == 403, res.text


async def test_metadata_write_cannot_follow_a_key_into_a_closed_folder(
    client: httpx.AsyncClient, owner_headers, env_id, monkeypatch
):
    from app.api import secrets

    uid = await _user(client, owner_headers, "writer", "developer")
    await _pol(client, owner_headers, uid, env_id, "/app", ["write"])
    writer = await login(client, "writer", PASS)
    await _put(client, owner_headers, env_id, "APP", "test-value", path="/app")
    route = f"/api/environments/{env_id}"
    requested, resume = asyncio.Event(), asyncio.Event()
    find_secret = secrets._secret_or_404

    async def wait_after_lookup(*args):
        secret = await find_secret(*args)
        if not requested.is_set():
            requested.set()
            await resume.wait()
        return secret

    monkeypatch.setattr(secrets, "_secret_or_404", wait_after_lookup)
    pending = asyncio.create_task(client.post(
        f"{route}/secret/meta", headers=writer,
        json={"name": "APP", "path": "/app", "note": "unexpected-change"},
    ))
    try:
        await asyncio.wait_for(requested.wait(), timeout=5)
        moved = await client.post(f"{route}/secret/rename", headers=owner_headers, json={
            "name": "APP", "path": "/app", "new_name": "APP", "new_path": "/private",
        })
        assert moved.status_code == 200, moved.text
    finally:
        resume.set()
    assert (await pending).status_code == 409
    rows = await client.get(f"{route}/secrets", headers=owner_headers)
    assert [(row["path"], row["note"]) for row in rows.json()] == [("/private", "")]


async def test_project_list_shows_only_visible_environments(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    _pid, envs = await _setup(client, owner_headers)
    uid = await _user(client, owner_headers, "narrow", "developer")
    await _pol(client, owner_headers, uid, envs["dev"], "/", ["list", "read"])
    narrow = await login(client, "narrow", PASS)
    rows = (await client.get("/api/projects", headers=narrow)).json()
    shop = next(r for r in rows if r["slug"] == "shop")
    assert shop["environments"] == ["dev"]
    assert shop["env_count"] == 1
    assert shop["secret_count"] == 0


async def test_folder_only_policy_opens_its_folder(client: httpx.AsyncClient, owner_headers, unsealed):
    _pid, envs = await _setup(client, owner_headers)
    prod = envs["prod"]
    uid = await _user(client, owner_headers, "folder", "developer")
    await _pol(client, owner_headers, uid, prod, "/private", ["list", "read"])
    folder = await login(client, "folder", PASS)
    listed = await client.get(f"/api/environments/{prod}/secrets", headers=folder)
    assert listed.status_code == 200, listed.text
    assert {r["name"] for r in listed.json()} == {"SECRET", "TOKEN"}
    briefs = await client.get("/api/environments", headers=folder)
    assert prod in {e["id"] for e in briefs.json()}
