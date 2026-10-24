"""Машинный контур не подменяет адрес проекта тезкой из другой группы.

Агент помнит проект вместе с группой. Раньше, если машина теряла право на
свой проект или его удаляли, а одноименный проект в соседней группе ей был
выдан, запрос с прежней группой молча получал значения тезки: агент
переписывал .env чужим проектом и перезапускал приложение. Подставлять можно
только проект, который действительно переехал с этого адреса.
"""

from tests.conftest import client, owner_headers, unsealed  # noqa: F401 - фикстуры


async def _project(client, oh, slug, group, value):
    res = await client.post(
        "/api/projects",
        headers=oh,
        json={"slug": slug, "title": slug, "group_name": group, "environments": ["prod"]},
    )
    assert res.status_code == 201, res.text
    pid = res.json()["id"]
    env = (await client.get(f"/api/projects/{pid}/environments", headers=oh)).json()[0]["id"]
    res = await client.put(
        f"/api/environments/{env}/secrets",
        headers=oh,
        json={"name": "DB_HOST", "value": value, "path": "/"},
    )
    assert res.status_code == 200, res.text
    return pid, env


async def _machine(client, oh, *envs):
    res = await client.post(
        "/api/machines",
        headers=oh,
        json={"name": "web-1", "description": "", "allow_ips": "", "expires_at": ""},
    )
    assert res.status_code == 201, res.text
    machine = res.json()
    policies = []
    for env in envs:
        res = await client.post(
            "/api/policies",
            headers=oh,
            json={
                "subject_type": "machine",
                "subject_id": machine["id"],
                "environment_id": env,
                "path_prefix": "/",
                "effect": "allow",
                "actions": ["read"],
            },
        )
        assert res.status_code == 201, res.text
        policies.append(res.json()["id"])
    res = await client.post(
        "/api/v1/machine/token",
        json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
    )
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}, policies


async def _read(client, mh, group, project="api"):
    params = {"project": project, "env": "prod", "group": group}
    return await client.get("/api/v1/machine/secrets", headers=mh, params=params)


def _host(res) -> str:
    assert res.status_code == 200, res.text
    return {r["name"]: r["value"] for r in res.json()["values"]}["DB_HOST"]


async def _move(client, oh, pid, group):
    res = await client.patch(f"/api/projects/{pid}", headers=oh, json={"group_name": group})
    assert res.status_code == 200, res.text


async def test_deleted_project_is_not_replaced_by_a_namesake(client, owner_headers, unsealed):
    oh = owner_headers
    acme, acme_env = await _project(client, oh, "api", "acme", "acme-db")
    _, globex_env = await _project(client, oh, "api", "globex", "globex-db")
    mh, _ = await _machine(client, oh, acme_env, globex_env)
    assert _host(await _read(client, mh, "acme")) == "acme-db"

    res = await client.delete(f"/api/projects/{acme}", headers=oh, params={"confirm": "api"})
    assert res.status_code == 204, res.text
    assert (await _read(client, mh, "acme")).status_code == 403
    assert _host(await _read(client, mh, "globex")) == "globex-db"


async def test_lost_grant_is_a_refusal_not_a_namesake(client, owner_headers, unsealed):
    oh = owner_headers
    _, acme_env = await _project(client, oh, "api", "acme", "acme-db")
    _, globex_env = await _project(client, oh, "api", "globex", "globex-db")
    mh, (acme_policy, _) = await _machine(client, oh, acme_env, globex_env)

    res = await client.delete(f"/api/policies/{acme_policy}", headers=oh)
    assert res.status_code == 204, res.text
    assert (await _read(client, mh, "acme")).status_code == 403


async def test_moved_project_is_still_found_by_its_old_address(client, owner_headers, unsealed):
    oh = owner_headers
    pid, env = await _project(client, oh, "api", "acme", "acme-db")
    mh, _ = await _machine(client, oh, env)
    await _move(client, oh, pid, "globex")
    assert _host(await _read(client, mh, "acme")) == "acme-db"
    # И после второго переезда: агент мог не видеть и первого.
    await _move(client, oh, pid, "initech")
    assert _host(await _read(client, mh, "acme")) == "acme-db"
    assert _host(await _read(client, mh, "globex")) == "acme-db"


async def test_new_project_at_the_old_address_takes_it_over(client, owner_headers, unsealed):
    """Проект уехал из acme, а на его место завели новый. Адрес теперь его,
    и машине без права на новый - отказ, а не переехавший проект."""
    oh = owner_headers
    pid, env = await _project(client, oh, "api", "acme", "old-db")
    mh, _ = await _machine(client, oh, env)
    await _move(client, oh, pid, "globex")
    await _project(client, oh, "api", "acme", "new-db")
    assert (await _read(client, mh, "acme")).status_code == 403


async def test_return_to_the_old_group_forgets_the_move(client, owner_headers, unsealed):
    oh = owner_headers
    pid, env = await _project(client, oh, "api", "acme", "acme-db")
    mh, _ = await _machine(client, oh, env)
    await _move(client, oh, pid, "globex")
    await _move(client, oh, pid, "acme")
    assert _host(await _read(client, mh, "acme")) == "acme-db"
    # Из globex проект ушел обратно, и этот адрес он помнит как прежний.
    assert _host(await _read(client, mh, "globex")) == "acme-db"


async def test_project_without_group_moved_into_one(client, owner_headers, unsealed):
    oh = owner_headers
    pid, env = await _project(client, oh, "api", "", "plain-db")
    _, other_env = await _project(client, oh, "api", "globex", "globex-db")
    mh, _ = await _machine(client, oh, env, other_env)
    assert _host(await _read(client, mh, "")) == "plain-db"
    await _move(client, oh, pid, "acme")
    # Тезка в globex выдан той же машине, но адрес без группы помнит переехавший.
    assert _host(await _read(client, mh, "")) == "plain-db"


async def test_address_without_group_needs_a_unique_name(client, owner_headers, unsealed):
    oh = owner_headers
    _, acme_env = await _project(client, oh, "api", "acme", "acme-db")
    mh, _ = await _machine(client, oh, acme_env)
    assert _host(await _read(client, mh, "")) == "acme-db"
    # Появился тезка, машине не выданный: без группы адрес уже неоднозначен.
    await _project(client, oh, "api", "globex", "globex-db")
    res = await _read(client, mh, "")
    assert res.status_code == 400, res.text
    assert _host(await _read(client, mh, "acme")) == "acme-db"


async def test_project_without_group_wins_the_address_without_group(
    client, owner_headers, unsealed
):
    oh = owner_headers
    _, plain_env = await _project(client, oh, "api", "", "plain-db")
    _, acme_env = await _project(client, oh, "api", "acme", "acme-db")
    mh, _ = await _machine(client, oh, plain_env, acme_env)
    assert _host(await _read(client, mh, "")) == "plain-db"
    assert _host(await _read(client, mh, "acme")) == "acme-db"
