"""Права по папкам: запрет на папку действует везде, а не только в чтении ключа.

Седьмой проход проверки нашел, что запрет на /private соблюдался в
GET /secret и обходился всем, что работает с окружением целиком: выгрузкой,
"всеми значениями", выгрузкой проекта, замечаниями, сравнением и "где еще
такое же значение" (оракул угадывания), снимками, машиной (своей подключенной
и с собственной политикой), сбросом пароля и переименованием "везде".
"""

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
