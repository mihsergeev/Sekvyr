"""Иерархия ролей: кто кем может распоряжаться."""

import httpx

from tests.conftest import login


async def _create(client, headers, username, role, password="member-pass-2026"):
    return await client.post(
        "/api/users",
        headers=headers,
        json={"username": username, "password": password, "role": role},
    )


async def test_owner_creates_and_lists(client: httpx.AsyncClient, owner_headers):
    res = await _create(client, owner_headers, "dev", "developer")
    assert res.status_code == 201, res.text
    assert res.json()["role"] == "developer"

    listed = await client.get("/api/users", headers=owner_headers)
    assert listed.status_code == 200
    assert {u["username"] for u in listed.json()} == {"owner", "dev"}


async def test_cannot_grant_role_at_or_above_own(client: httpx.AsyncClient, owner_headers):
    await _create(client, owner_headers, "boss", "maintainer")
    boss = await login(client, "boss", "member-pass-2026")

    # ответственный не заводит ответственного и уж тем более владельца
    assert (await _create(client, boss, "peer", "maintainer")).status_code == 403
    assert (await _create(client, boss, "root2", "owner")).status_code == 403
    # ...но роль ниже своей - пожалуйста
    assert (await _create(client, boss, "dev", "developer")).status_code == 201


async def test_cannot_touch_equal_or_higher(client: httpx.AsyncClient, owner_headers):
    await _create(client, owner_headers, "boss", "maintainer")
    await _create(client, owner_headers, "boss2", "maintainer")
    boss = await login(client, "boss", "member-pass-2026")

    users = {u["username"]: u["id"] for u in (await client.get("/api/users", headers=owner_headers)).json()}
    # равного трогать нельзя
    assert (
        await client.patch(f"/api/users/{users['boss2']}", headers=boss, json={"disabled": True})
    ).status_code == 403
    # владельца тем более
    assert (
        await client.patch(f"/api/users/{users['owner']}", headers=boss, json={"disabled": True})
    ).status_code == 403


async def test_viewer_cannot_change_anything(client: httpx.AsyncClient, owner_headers):
    await _create(client, owner_headers, "watcher", "viewer")
    watcher = await login(client, "watcher", "member-pass-2026")
    res = await _create(client, watcher, "someone", "viewer")
    assert res.status_code == 403


async def test_last_owner_is_protected(client: httpx.AsyncClient, owner_headers):
    """Единственного владельца нельзя ни отключить, ни разжаловать - иначе
    панель останется без того, кто может выдать права."""
    users = {u["username"]: u["id"] for u in (await client.get("/api/users", headers=owner_headers)).json()}
    owner_id = users["owner"]
    assert (
        await client.patch(f"/api/users/{owner_id}", headers=owner_headers, json={"disabled": True})
    ).status_code == 403  # себя трогать нельзя вовсе: роль не строго ниже


async def test_disabled_user_cannot_log_in(client: httpx.AsyncClient, owner_headers):
    await _create(client, owner_headers, "dev", "developer")
    dev_headers = await login(client, "dev", "member-pass-2026")
    users = {u["username"]: u["id"] for u in (await client.get("/api/users", headers=owner_headers)).json()}

    res = await client.patch(
        f"/api/users/{users['dev']}", headers=owner_headers, json={"disabled": True}
    )
    assert res.status_code == 200

    # выданный ранее токен перестает работать сразу, а не по истечении срока
    assert (await client.get("/api/auth/me", headers=dev_headers)).status_code == 401
    fresh = await client.post(
        "/api/auth/login", json={"username": "dev", "password": "member-pass-2026"}
    )
    assert fresh.status_code == 401


async def test_password_reset_by_superior(client: httpx.AsyncClient, owner_headers):
    await _create(client, owner_headers, "dev", "developer")
    dev_headers = await login(client, "dev", "member-pass-2026")
    users = {u["username"]: u["id"] for u in (await client.get("/api/users", headers=owner_headers)).json()}

    res = await client.post(
        f"/api/users/{users['dev']}/password",
        headers=owner_headers,
        json={"new_password": "reset-pass-2026"},
    )
    assert res.status_code == 204
    assert (await client.get("/api/auth/me", headers=dev_headers)).status_code == 401
    assert await login(client, "dev", "reset-pass-2026")


async def test_developer_does_not_see_user_list(client: httpx.AsyncClient, owner_headers):
    await _create(client, owner_headers, "dev", "developer")
    dev_headers = await login(client, "dev", "member-pass-2026")
    assert (await client.get("/api/users", headers=dev_headers)).status_code == 403

async def test_user_allow_ips_cuts_off_other_addresses(
    client: httpx.AsyncClient, owner_headers
):
    """Учетной записи можно задать, откуда пускать: украденный пароль перестает
    работать откуда угодно.

    Проверка идет на каждом запросе, а не только при входе, - иначе токен,
    уехавший вместе с сессией, доживал бы свой срок с чужого адреса.
    """
    made = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "remote", "password": "длинный-пароль-1234", "role": "developer"},
    )
    assert made.status_code == 201, made.text
    user_id = made.json()["id"]

    token = (
        await client.post(
            "/api/auth/login",
            json={"username": "remote", "password": "длинный-пароль-1234"},
        )
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert (await client.get("/api/projects", headers=headers)).status_code == 200

    # Разрешаем только чужую сеть - своих запросов это уже не пускает.
    patched = await client.patch(
        f"/api/users/{user_id}", headers=owner_headers, json={"allow_ips": "10.20.30.0/24"}
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["allow_ips"] == "10.20.30.0/24"

    closed = await client.get("/api/projects", headers=headers)
    assert closed.status_code == 403

    # Пустой список возвращает прежнее поведение.
    await client.patch(f"/api/users/{user_id}", headers=owner_headers, json={"allow_ips": ""})
    assert (await client.get("/api/projects", headers=headers)).status_code == 200


async def test_user_allow_ips_rejects_nonsense(client: httpx.AsyncClient, owner_headers):
    """Опечатка в подсети должна всплыть здесь, а не тем, что человек однажды
    не сможет войти."""
    made = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "typo", "password": "длинный-пароль-1234", "role": "viewer"},
    )
    res = await client.patch(
        f"/api/users/{made.json()['id']}",
        headers=owner_headers,
        json={"allow_ips": "10.0.0.0/8 не-адрес"},
    )
    assert res.status_code == 400


async def test_password_reset_needs_the_same_rights(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Задать чужой пароль - значит войти под этим именем со всеми его правами:
    ответственный без доступа к проду не входит туда через разработчика."""
    dev = await _create(client, owner_headers, "dev", "developer")
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "user",
            "subject_id": dev.json()["id"],
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": ["list", "read"],
            "effect": "allow",
        },
    )
    keeper = await _create(client, owner_headers, "keeper", "maintainer", "keeper-pass-2026")
    keeper_headers = await login(client, "keeper", "keeper-pass-2026")
    res = await client.post(
        f"/api/users/{dev.json()['id']}/password",
        headers=keeper_headers,
        json={"new_password": "taken-over-2026"},
    )
    assert res.status_code == 403, res.text
    assert (
        await client.post(
            "/api/auth/login", json={"username": "dev", "password": "taken-over-2026"}
        )
    ).status_code == 401

    # С теми же правами - можно: это обычный случай "человек забыл пароль".
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "user",
            "subject_id": keeper.json()["id"],
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": ["list", "read"],
            "effect": "allow",
        },
    )
    res = await client.post(
        f"/api/users/{dev.json()['id']}/password",
        headers=keeper_headers,
        json={"new_password": "forgot-it-2026"},
    )
    assert res.status_code == 204, res.text
