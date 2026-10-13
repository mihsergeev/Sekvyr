"""Политики доступа: кто, где и что может."""

import httpx
from datetime import datetime, timedelta, timezone

from tests.conftest import login

PASS = "member-pass-2026"


async def _user(client, owner_headers, name, role="developer") -> int:
    res = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": name, "password": PASS, "role": role},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _policy(client, owner_headers, **body):
    body.setdefault("subject_type", "user")
    body.setdefault("effect", "allow")
    return await client.post("/api/policies", headers=owner_headers, json=body)


async def _list(client, headers, env_id):
    return await client.get(f"/api/environments/{env_id}/secrets", headers=headers)


async def _value(client, headers, env_id, name, path="/"):
    return await client.get(
        f"/api/environments/{env_id}/secret", headers=headers, params={"name": name, "path": path}
    )


async def test_no_policy_means_no_access(client: httpx.AsyncClient, owner_headers, env_id):
    """Новая учетка не видит ничего, пока права не выданы. Закрыто по умолчанию -
    иначе "забыли настроить" означает "всем все видно"."""
    await _user(client, owner_headers, "newbie")
    dev = await login(client, "newbie", PASS)
    assert (await client.get("/api/projects", headers=dev)).json() == []
    assert (await _list(client, dev, env_id)).status_code == 403


async def test_owner_needs_no_policies(client: httpx.AsyncClient, owner_headers, env_id):
    """Иначе первым же действием можно запереть самого себя."""
    assert (await _list(client, owner_headers, env_id)).status_code == 200
    assert (await client.get("/api/policies", headers=owner_headers)).json() == []


async def test_policy_is_limited_to_its_environment(
    client: httpx.AsyncClient, owner_headers, env_id
):
    project_id = (await client.get("/api/projects", headers=owner_headers)).json()[0]["id"]
    other = await client.post(
        f"/api/projects/{project_id}/environments", headers=owner_headers, json={"name": "stage"}
    )
    other_id = other.json()["id"]
    await client.put(
        f"/api/environments/{env_id}/secrets", headers=owner_headers, json={"name": "A", "value": "prod"}
    )
    await client.put(
        f"/api/environments/{other_id}/secrets", headers=owner_headers, json={"name": "A", "value": "stage"}
    )

    dev_id = await _user(client, owner_headers, "dev")
    await _policy(
        client, owner_headers, subject_id=dev_id, environment_id=other_id, actions=["list", "read"]
    )
    dev = await login(client, "dev", PASS)

    assert (await _value(client, dev, other_id, "A")).json()["value"] == "stage"
    assert (await _value(client, dev, env_id, "A")).status_code == 403


async def test_path_prefix_limits_access(client: httpx.AsyncClient, owner_headers, env_id):
    for path, name in (("/db", "PASS"), ("/db/replica", "PASS"), ("/mail", "PASS")):
        await client.put(
            f"/api/environments/{env_id}/secrets",
            headers=owner_headers,
            json={"name": name, "value": "секрет", "path": path},
        )
    dev_id = await _user(client, owner_headers, "dev")
    await _policy(
        client, owner_headers, subject_id=dev_id, path_prefix="/db", actions=["list", "read"]
    )
    dev = await login(client, "dev", PASS)

    assert (await _value(client, dev, env_id, "PASS", "/db")).status_code == 200
    # вложенный путь входит в область
    assert (await _value(client, dev, env_id, "PASS", "/db/replica")).status_code == 200
    # соседний - нет
    assert (await _value(client, dev, env_id, "PASS", "/mail")).status_code == 403


async def test_deny_beats_allow(client: httpx.AsyncClient, owner_headers, env_id):
    """Отобрать доступ должно быть одним действием, а не поиском всех мест, где
    он был выдан."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "PROD_KEY", "value": "секрет", "path": "/prod"},
    )
    dev_id = await _user(client, owner_headers, "dev")
    await _policy(client, owner_headers, subject_id=dev_id, actions=["list", "read"])
    await _policy(
        client,
        owner_headers,
        subject_id=dev_id,
        path_prefix="/prod",
        actions=["read"],
        effect="deny",
    )
    dev = await login(client, "dev", PASS)
    assert (await _list(client, dev, env_id)).status_code == 200
    assert (await _value(client, dev, env_id, "PROD_KEY", "/prod")).status_code == 403


async def test_expired_policy_stops_working(client: httpx.AsyncClient, owner_headers, env_id):
    dev_id = await _user(client, owner_headers, "contractor")
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    expired = await _policy(
        client, owner_headers, subject_id=dev_id, actions=["list"], expires_at=past
    )
    assert expired.status_code == 201
    assert expired.json()["expired"] is True

    dev = await login(client, "contractor", PASS)
    assert (await _list(client, dev, env_id)).status_code == 403

    await _policy(client, owner_headers, subject_id=dev_id, actions=["list"], expires_at=future)
    assert (await _list(client, dev, env_id)).status_code == 200


async def test_policy_can_demand_second_factor(client: httpx.AsyncClient, owner_headers, env_id):
    """Право с требованием второго фактора не действует, пока фактор не включен:
    это условие доступа, а не напоминание включить."""
    dev_id = await _user(client, owner_headers, "dev")
    await _policy(client, owner_headers, subject_id=dev_id, actions=["list"], require_2fa=True)
    dev = await login(client, "dev", PASS)
    assert (await _list(client, dev, env_id)).status_code == 403


async def test_group_policy_applies_to_members(client: httpx.AsyncClient, owner_headers, env_id):
    dev_id = await _user(client, owner_headers, "dev")
    group = await client.post("/api/groups", headers=owner_headers, json={"name": "backend"})
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    await _policy(
        client, owner_headers, subject_type="group", subject_id=group_id, actions=["list"]
    )

    dev = await login(client, "dev", PASS)
    assert (await _list(client, dev, env_id)).status_code == 403  # пока не в группе

    await client.post(
        f"/api/groups/{group_id}/members", headers=owner_headers, json={"user_id": dev_id}
    )
    assert (await _list(client, dev, env_id)).status_code == 200

    # вывели из группы - доступ ушел вместе с ней
    await client.delete(f"/api/groups/{group_id}/members/{dev_id}", headers=owner_headers)
    assert (await _list(client, dev, env_id)).status_code == 403


async def test_deleting_group_removes_its_policies(client: httpx.AsyncClient, owner_headers):
    group = await client.post("/api/groups", headers=owner_headers, json={"name": "temp"})
    group_id = group.json()["id"]
    await _policy(
        client, owner_headers, subject_type="group", subject_id=group_id, actions=["list"]
    )
    await client.delete(f"/api/groups/{group_id}", headers=owner_headers)
    # политик, указывающих в пустоту, остаться не должно
    assert (await client.get("/api/policies", headers=owner_headers)).json() == []


async def test_only_owner_grants_rights(client: httpx.AsyncClient, owner_headers, env_id):
    """Право выдавать права - это и есть главный доступ."""
    boss_id = await _user(client, owner_headers, "boss", role="maintainer")
    await _policy(client, owner_headers, subject_id=boss_id, actions=["list", "read", "write"])
    boss = await login(client, "boss", PASS)

    assert (await client.get("/api/policies", headers=boss)).status_code == 403
    res = await client.post(
        "/api/policies",
        headers=boss,
        json={"subject_type": "user", "subject_id": boss_id, "actions": ["approve"]},
    )
    assert res.status_code == 403
    assert (await client.post("/api/groups", headers=boss, json={"name": "x"})).status_code == 403


async def test_permissions_endpoint_tells_the_ui_what_to_draw(
    client: httpx.AsyncClient, owner_headers, env_id
):
    dev_id = await _user(client, owner_headers, "dev")
    await _policy(client, owner_headers, subject_id=dev_id, actions=["list"])
    dev = await login(client, "dev", PASS)
    res = await client.get(f"/api/environments/{env_id}/permissions", headers=dev)
    assert res.status_code == 200
    assert res.json() == {
        "list": True,
        "read": False,
        "write": False,
        "delete": False,
        "rotate": False,
        "approve": False,
    }


async def test_write_policy_without_read(client: httpx.AsyncClient, owner_headers, env_id):
    """Записать, не имея права прочитать, - рабочий сценарий: приложение кладет
    новый токен, а человек, который его положил, значения не видит."""
    dev_id = await _user(client, owner_headers, "dev")
    await _policy(client, owner_headers, subject_id=dev_id, actions=["list", "write"])
    dev = await login(client, "dev", PASS)

    res = await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=dev,
        json={"name": "NEW_TOKEN", "value": "значение"},
    )
    assert res.status_code == 200
    assert (await _value(client, dev, env_id, "NEW_TOKEN")).status_code == 403
    assert (await _value(client, owner_headers, env_id, "NEW_TOKEN")).json()["value"] == "значение"


async def test_viewer_only_reads_whatever_is_granted(client: httpx.AsyncClient, owner_headers, env_id):
    """Наблюдатель смотрит, но не меняет - даже если право "менять" пришло через
    группу. Лично выдать ему такое право нельзя вовсе."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "секрет"},
    )
    created = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "watcher", "password": "member-pass-2026", "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    watcher_id = created.json()["id"]

    direct = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={"subject_type": "user", "subject_id": watcher_id, "actions": ["list", "read", "write"]},
    )
    assert direct.status_code == 400

    group = await client.post("/api/groups", headers=owner_headers, json={"name": "ops"})
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    joined = await client.post(
        f"/api/groups/{group_id}/members", headers=owner_headers, json={"user_id": watcher_id}
    )
    assert joined.status_code in (200, 201, 204), joined.text
    granted = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={"subject_type": "group", "subject_id": group_id, "actions": ["list", "read", "write"]},
    )
    assert granted.status_code == 201, granted.text

    watcher = await login(client, "watcher", "member-pass-2026")
    read = await client.get(
        f"/api/environments/{env_id}/secret", headers=watcher, params={"name": "DB_PASSWORD"}
    )
    assert read.status_code == 200 and read.json()["value"] == "секрет"
    write = await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=watcher,
        json={"name": "DB_PASSWORD", "value": "чужое"},
    )
    assert write.status_code == 403


async def test_developer_cannot_create_accounts(client: httpx.AsyncClient, owner_headers):
    """Учетки заводит ответственный и выше: раздела учетных записей разработчику
    не видно, и заводить их в обход интерфейса он тоже не должен."""
    created = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "dev", "password": "member-pass-2026", "role": "developer"},
    )
    assert created.status_code == 201, created.text
    dev = await login(client, "dev", "member-pass-2026")
    res = await client.post(
        "/api/users",
        headers=dev,
        json={"username": "someone", "password": "member-pass-2026", "role": "viewer"},
    )
    assert res.status_code == 403


async def test_environments_of_a_project_are_listed_by_rights(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Окружения проекта видно там, где есть право, а чужой проект - не видно
    вовсе: раньше этот маршрут отдавал их по номеру кому угодно."""
    res = await client.post(
        "/api/projects", headers=owner_headers, json={"slug": "shop", "environments": ["dev", "prod"]}
    )
    project = res.json()["id"]
    envs = {
        e["name"]: e["id"]
        for e in (
            await client.get(f"/api/projects/{project}/environments", headers=owner_headers)
        ).json()
    }
    uid = await _user(client, owner_headers, "dev")
    await _policy(
        client, owner_headers, subject_id=uid, environment_id=envs["dev"], path_prefix="/db",
        actions=["list", "read"],
    )
    dev = await login(client, "dev", PASS)
    listed = await client.get(f"/api/projects/{project}/environments", headers=dev)
    assert listed.status_code == 200
    assert [e["name"] for e in listed.json()] == ["dev"]

    stranger_id = await _user(client, owner_headers, "stranger")
    assert stranger_id
    stranger = await login(client, "stranger", PASS)
    assert (await client.get(f"/api/projects/{project}/environments", headers=stranger)).status_code == 404
    assert (await client.get(f"/api/projects/{project}/export", headers=stranger)).status_code == 404
    exported = await client.get(f"/api/projects/{project}/export", headers=dev)
    # prod человеку не видно - и в пропущенных его нет.
    assert exported.json()["skipped"] == ["dev"]
