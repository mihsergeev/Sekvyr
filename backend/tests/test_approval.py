"""Подтверждение изменений ролью выше."""

import httpx

from tests.conftest import login

PASS = "member-pass-2026"


async def _user(client, owner_headers, name, role) -> int:
    res = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": name, "password": PASS, "role": role},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _grant(client, owner_headers, user_id, actions):
    res = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={"subject_type": "user", "subject_id": user_id, "actions": actions},
    )
    assert res.status_code == 201, res.text


async def _set_threshold(client, owner_headers, level: int):
    project_id = (await client.get("/api/projects", headers=owner_headers)).json()[0]["id"]
    res = await client.patch(
        f"/api/projects/{project_id}", headers=owner_headers, json={"approval_min_level": level}
    )
    assert res.status_code == 200, res.text


async def _value(client, headers, env_id, name):
    return await client.get(
        f"/api/environments/{env_id}/secret", headers=headers, params={"name": name}
    )


async def test_edit_below_threshold_waits(client: httpx.AsyncClient, owner_headers, env_id):
    """Правка от роли ниже порога видна в истории, но приложения продолжают
    получать прежнее значение."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "было"},
    )
    await _set_threshold(client, owner_headers, 30)  # ответственный и выше правят сразу
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _grant(client, owner_headers, dev_id, ["list", "read", "write"])
    dev = await login(client, "dev", PASS)

    res = await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=dev,
        json={"name": "DB_PASSWORD", "value": "стало", "comment": "меняю пароль"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["pending"] is True

    # значение не изменилось
    assert (await _value(client, owner_headers, env_id, "DB_PASSWORD")).json()["value"] == "было"

    # но в списке видно, что правка ждет
    listed = await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    assert listed.json()[0]["pending"] is True

    waiting = await client.get(f"/api/environments/{env_id}/pending", headers=owner_headers)
    assert [w["name"] for w in waiting.json()] == ["DB_PASSWORD"]
    assert waiting.json()[0]["author"] == "dev"


async def test_approval_applies_the_change(client: httpx.AsyncClient, owner_headers, env_id):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "TOKEN", "value": "было"},
    )
    await _set_threshold(client, owner_headers, 30)
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _grant(client, owner_headers, dev_id, ["list", "read", "write"])
    dev = await login(client, "dev", PASS)
    put = await client.put(
        f"/api/environments/{env_id}/secrets", headers=dev, json={"name": "TOKEN", "value": "стало"}
    )
    version = put.json()["version"]

    res = await client.post(
        f"/api/environments/{env_id}/secret/approve",
        headers=owner_headers,
        json={"name": "TOKEN", "version": version, "note": "ок"},
    )
    assert res.status_code == 200, res.text
    assert (await _value(client, owner_headers, env_id, "TOKEN")).json()["value"] == "стало"

    log = await client.get("/api/audit", headers=owner_headers)
    assert "secret_approved" in [e["action"] for e in log.json()["entries"]]


async def test_author_cannot_approve_himself(client: httpx.AsyncClient, owner_headers, env_id):
    """Иначе согласование превращается в кнопку "применить в два клика"."""
    await _set_threshold(client, owner_headers, 30)
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _grant(client, owner_headers, dev_id, ["list", "read", "write", "approve"])
    dev = await login(client, "dev", PASS)
    put = await client.put(
        f"/api/environments/{env_id}/secrets", headers=dev, json={"name": "A", "value": "x"}
    )
    res = await client.post(
        f"/api/environments/{env_id}/secret/approve",
        headers=dev,
        json={"name": "A", "version": put.json()["version"]},
    )
    assert res.status_code == 403
    assert "кто-то другой" in res.json()["detail"]


async def test_equal_role_cannot_approve(client: httpx.AsyncClient, owner_headers, env_id):
    await _set_threshold(client, owner_headers, 30)
    first = await _user(client, owner_headers, "dev1", "developer")
    second = await _user(client, owner_headers, "dev2", "developer")
    await _grant(client, owner_headers, first, ["list", "write"])
    await _grant(client, owner_headers, second, ["list", "write", "approve"])
    author = await login(client, "dev1", PASS)
    peer = await login(client, "dev2", PASS)

    put = await client.put(
        f"/api/environments/{env_id}/secrets", headers=author, json={"name": "A", "value": "x"}
    )
    res = await client.post(
        f"/api/environments/{env_id}/secret/approve",
        headers=peer,
        json={"name": "A", "version": put.json()["version"]},
    )
    assert res.status_code == 403
    assert "выше" in res.json()["detail"]


async def test_rejection_keeps_the_old_value(client: httpx.AsyncClient, owner_headers, env_id):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "TOKEN", "value": "было"},
    )
    await _set_threshold(client, owner_headers, 30)
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _grant(client, owner_headers, dev_id, ["list", "write"])
    dev = await login(client, "dev", PASS)
    put = await client.put(
        f"/api/environments/{env_id}/secrets", headers=dev, json={"name": "TOKEN", "value": "стало"}
    )

    res = await client.post(
        f"/api/environments/{env_id}/secret/reject",
        headers=owner_headers,
        json={"name": "TOKEN", "version": put.json()["version"], "note": "не тот пароль"},
    )
    assert res.status_code == 204
    assert (await _value(client, owner_headers, env_id, "TOKEN")).json()["value"] == "было"

    # отказ остается в истории вместе с причиной
    history = await client.get(
        f"/api/environments/{env_id}/secret/history",
        headers=owner_headers,
        params={"name": "TOKEN"},
    )
    assert len(history.json()) == 2
    assert (await client.get(f"/api/environments/{env_id}/pending", headers=owner_headers)).json() == []


async def test_maintainer_edits_without_waiting(client: httpx.AsyncClient, owner_headers, env_id):
    """Порог по роли: кто в проекте главный, тот правит сразу."""
    await _set_threshold(client, owner_headers, 30)
    boss_id = await _user(client, owner_headers, "boss", "maintainer")
    await _grant(client, owner_headers, boss_id, ["list", "read", "write"])
    boss = await login(client, "boss", PASS)
    res = await client.put(
        f"/api/environments/{env_id}/secrets", headers=boss, json={"name": "A", "value": "сразу"}
    )
    assert res.json()["pending"] is False
    assert (await _value(client, boss, env_id, "A")).json()["value"] == "сразу"


async def test_threshold_is_owner_only(client: httpx.AsyncClient, owner_headers, env_id):
    """Иначе тот, чьи правки должны подтверждаться, первым делом отключит
    подтверждение."""
    boss_id = await _user(client, owner_headers, "boss", "maintainer")
    await _grant(client, owner_headers, boss_id, ["list", "read", "write"])
    boss = await login(client, "boss", PASS)
    project_id = (await client.get("/api/projects", headers=boss)).json()[0]["id"]
    res = await client.patch(
        f"/api/projects/{project_id}", headers=boss, json={"approval_min_level": 0}
    )
    assert res.status_code == 403
