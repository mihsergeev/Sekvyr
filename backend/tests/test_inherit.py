"""Наследование окружений: десять стендов с общими значениями."""

import httpx


async def _project(client, owner_headers) -> int:
    res = await client.get("/api/projects", headers=owner_headers)
    return res.json()[0]["id"]


async def _env(client, owner_headers, project_id, name, parent_id=None) -> int:
    res = await client.post(
        f"/api/projects/{project_id}/environments",
        headers=owner_headers,
        json={"name": name, "parent_id": parent_id},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _put(client, headers, env_id, name, value, path="/"):
    return await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )


async def _value(client, headers, env_id, name, path="/"):
    return await client.get(
        f"/api/environments/{env_id}/secret", headers=headers, params={"name": name, "path": path}
    )


async def test_child_reads_parent_values(client: httpx.AsyncClient, owner_headers, env_id):
    """Ради этого все и затевалось: общее задается один раз, а не копируется в
    десять стендов, где потом молча расходится."""
    project_id = await _project(client, owner_headers)
    base = await _env(client, owner_headers, project_id, "tech-base")
    tech1 = await _env(client, owner_headers, project_id, "tech1", parent_id=base)

    await _put(client, owner_headers, base, "SENTRY_DSN", "общий-dsn")
    await _put(client, owner_headers, base, "DB_HOST", "db-общий")

    listed = await client.get(f"/api/environments/{tech1}/secrets", headers=owner_headers)
    assert {r["name"] for r in listed.json()} == {"SENTRY_DSN", "DB_HOST"}
    assert all(r["inherited_from"] == "tech-base" for r in listed.json())
    assert (await _value(client, owner_headers, tech1, "SENTRY_DSN")).json()["value"] == "общий-dsn"


async def test_override_wins_and_can_be_dropped(
    client: httpx.AsyncClient, owner_headers, env_id
):
    project_id = await _project(client, owner_headers)
    base = await _env(client, owner_headers, project_id, "tech-base")
    tech1 = await _env(client, owner_headers, project_id, "tech1", parent_id=base)
    await _put(client, owner_headers, base, "DB_HOST", "db-общий")
    await _put(client, owner_headers, tech1, "DB_HOST", "db-местный")

    assert (await _value(client, owner_headers, tech1, "DB_HOST")).json()["value"] == "db-местный"
    listed = await client.get(f"/api/environments/{tech1}/secrets", headers=owner_headers)
    assert listed.json()[0]["inherited_from"] == ""
    # база не изменилась: переопределение живет в дочернем окружении
    assert (await _value(client, owner_headers, base, "DB_HOST")).json()["value"] == "db-общий"

    res = await client.post(
        f"/api/environments/{tech1}/secret/inherit",
        headers=owner_headers,
        json={"name": "DB_HOST"},
    )
    assert res.status_code == 200, res.text
    assert (await _value(client, owner_headers, tech1, "DB_HOST")).json()["value"] == "db-общий"
    listed = await client.get(f"/api/environments/{tech1}/secrets", headers=owner_headers)
    assert listed.json()[0]["inherited_from"] == "tech-base"

    # история переопределения осталась: видно, что оно было и когда снято
    history = await client.get(
        f"/api/environments/{tech1}/secret/history",
        headers=owner_headers,
        params={"name": "DB_HOST"},
    )
    assert len(history.json()) == 2


async def test_deletion_hides_inherited_key(client: httpx.AsyncClient, owner_headers, env_id):
    """Удалили в стенде - значит здесь этого ключа нет. Воскрешать значение из
    родителя было бы сюрпризом ровно в тот момент, когда его убирали намеренно."""
    project_id = await _project(client, owner_headers)
    base = await _env(client, owner_headers, project_id, "tech-base")
    tech1 = await _env(client, owner_headers, project_id, "tech1", parent_id=base)
    await _put(client, owner_headers, base, "LEGACY", "старое")
    await _put(client, owner_headers, tech1, "LEGACY", "местное")

    res = await client.delete(
        f"/api/environments/{tech1}/secret", headers=owner_headers, params={"name": "LEGACY"}
    )
    assert res.status_code == 204
    assert (await _value(client, owner_headers, tech1, "LEGACY")).status_code == 404
    assert (await _value(client, owner_headers, base, "LEGACY")).json()["value"] == "старое"


async def test_export_includes_inherited(client: httpx.AsyncClient, owner_headers, env_id):
    """Файл нужен, чтобы поднять приложение, а приложению все равно, где значение
    задано."""
    project_id = await _project(client, owner_headers)
    base = await _env(client, owner_headers, project_id, "tech-base")
    tech1 = await _env(client, owner_headers, project_id, "tech1", parent_id=base)
    await _put(client, owner_headers, base, "SHARED", "общее")
    await _put(client, owner_headers, tech1, "OWN", "своё")

    dump = (await client.get(f"/api/environments/{tech1}/export", headers=owner_headers)).json()
    assert "SHARED='общее'" in dump["text"]
    assert "OWN='своё'" in dump["text"]


async def test_chain_of_three_levels(client: httpx.AsyncClient, owner_headers, env_id):
    project_id = await _project(client, owner_headers)
    root = await _env(client, owner_headers, project_id, "common")
    middle = await _env(client, owner_headers, project_id, "tech-base", parent_id=root)
    leaf = await _env(client, owner_headers, project_id, "tech7", parent_id=middle)
    await _put(client, owner_headers, root, "A", "из корня")
    await _put(client, owner_headers, middle, "B", "из середины")
    await _put(client, owner_headers, leaf, "C", "своё")

    listed = await client.get(f"/api/environments/{leaf}/secrets", headers=owner_headers)
    got = {r["name"]: r["inherited_from"] for r in listed.json()}
    assert got == {"A": "common", "B": "tech-base", "C": ""}


async def test_cycles_are_refused(client: httpx.AsyncClient, owner_headers, env_id):
    """Два стенда, назначенные родителями друг другу, увели бы чтение любого
    ключа в бесконечность."""
    project_id = await _project(client, owner_headers)
    a = await _env(client, owner_headers, project_id, "a")
    b = await _env(client, owner_headers, project_id, "b", parent_id=a)

    res = await client.patch(
        f"/api/environments/{a}", headers=owner_headers, json={"parent_id": b}
    )
    assert res.status_code == 400
    assert "круг" in res.json()["detail"]

    itself = await client.patch(
        f"/api/environments/{a}", headers=owner_headers, json={"parent_id": a}
    )
    assert itself.status_code == 400


async def test_parent_must_be_in_the_same_project(
    client: httpx.AsyncClient, owner_headers, env_id
):
    project_id = await _project(client, owner_headers)
    other = await client.post(
        "/api/projects", headers=owner_headers, json={"slug": "other-project"}
    )
    other_env = await _env(client, owner_headers, other.json()["id"], "prod")

    res = await client.post(
        f"/api/projects/{project_id}/environments",
        headers=owner_headers,
        json={"name": "borrowed", "parent_id": other_env},
    )
    assert res.status_code == 400


async def test_project_list_carries_counts(client: httpx.AsyncClient, owner_headers, env_id):
    """На сотне проектов список без счетчиков - это сотня одинаковых строк."""
    await _put(client, owner_headers, env_id, "A", "one")
    await _put(client, owner_headers, env_id, "B", "two")
    res = await client.get("/api/projects", headers=owner_headers)
    project = res.json()[0]
    assert project["env_count"] == 1
    assert project["secret_count"] == 2
    assert project["pending_count"] == 0


async def test_environment_list_shows_own_and_inherited_counts(
    client: httpx.AsyncClient, owner_headers, env_id
):
    project_id = await _project(client, owner_headers)
    base = await _env(client, owner_headers, project_id, "tech-base")
    tech1 = await _env(client, owner_headers, project_id, "tech1", parent_id=base)
    await _put(client, owner_headers, base, "SHARED", "общее")
    await _put(client, owner_headers, tech1, "OWN", "своё")

    rows = (
        await client.get(f"/api/projects/{project_id}/environments", headers=owner_headers)
    ).json()
    by_name = {r["name"]: r for r in rows}
    assert by_name["tech1"]["parent_name"] == "tech-base"
    assert by_name["tech1"]["secret_count"] == 2  # свое плюс унаследованное
    assert by_name["tech1"]["own_count"] == 1


async def _maintainer(client, owner_headers, name, grants) -> dict[str, str]:
    """Ответственный с правами только через политики: grants - это
    (окружение, папка, действия, разрешить ли)."""
    from tests.conftest import login

    user = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": name, "password": "keeper-pass-2026", "role": "maintainer"},
    )
    assert user.status_code == 201, user.text
    for env, path, actions, allow in grants:
        res = await client.post(
            "/api/policies",
            headers=owner_headers,
            json={
                "subject_type": "user",
                "subject_id": user.json()["id"],
                "environment_id": env,
                "path_prefix": path,
                "actions": actions,
                "effect": "allow" if allow else "deny",
            },
        )
        assert res.status_code == 201, res.text
    return await login(client, name, "keeper-pass-2026")


async def test_parent_must_be_readable_in_full(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Наследник отдает значения родителя всем, кто читает его самого. Без этой
    проверки ответственный со своим стендом назначал ему родителем прод, к
    которому прав не имел, и читал прод через стенд."""
    project_id = await _project(client, owner_headers)
    stage = await _env(client, owner_headers, project_id, "stage")
    await _put(client, owner_headers, env_id, "DB_PASSWORD", "прод-пароль")
    await _put(client, owner_headers, env_id, "CARD_KEY", "ключ-платежей", path="/pay")
    rw = ["list", "read", "write"]
    keeper = await _maintainer(client, owner_headers, "keeper", [(stage, "/", rw, True)])

    res = await client.patch(
        f"/api/environments/{stage}", headers=keeper, json={"parent_id": env_id}
    )
    assert res.status_code == 403, res.text
    assert (await _value(client, keeper, stage, "DB_PASSWORD")).status_code == 404

    # Запрет на папку родителя наследованием тоже не обходится.
    partial = await _maintainer(
        client,
        owner_headers,
        "partial",
        [(stage, "/", rw, True), (env_id, "/", ["list", "read"], True), (env_id, "/pay", ["read"], False)],
    )
    res = await client.patch(
        f"/api/environments/{stage}", headers=partial, json={"parent_id": env_id}
    )
    assert res.status_code == 403, res.text

    full = await _maintainer(
        client,
        owner_headers,
        "full",
        [(stage, "/", rw, True), (env_id, "/", ["list", "read"], True)],
    )
    res = await client.patch(f"/api/environments/{stage}", headers=full, json={"parent_id": env_id})
    assert res.status_code == 200, res.text
    assert res.json()["parent_id"] == env_id


async def test_environment_is_changed_only_with_write(
    client: httpx.AsyncClient, owner_headers, env_id
):
    project_id = await _project(client, owner_headers)
    base = await _env(client, owner_headers, project_id, "tech-base")
    tech1 = await _env(client, owner_headers, project_id, "tech1", parent_id=base)
    reader = await _maintainer(
        client, owner_headers, "reader", [(tech1, "/", ["list", "read"], True)]
    )
    res = await client.patch(f"/api/environments/{tech1}", headers=reader, json={"parent_id": None})
    assert res.status_code == 403, res.text
    res = await client.patch(f"/api/environments/{tech1}", headers=reader, json={"title": "x"})
    assert res.status_code == 403, res.text

    # Правка одного названия наследование не снимает.
    res = await client.patch(
        f"/api/environments/{tech1}", headers=owner_headers, json={"title": "Первый стенд"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["parent_id"] == base


async def test_new_environment_takes_only_what_is_readable(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Копия и родитель при создании - тот же доступ к значениям источника."""
    project_id = await _project(client, owner_headers)
    await _put(client, owner_headers, env_id, "DB_PASSWORD", "прод-пароль")
    keeper = await _maintainer(client, owner_headers, "keeper", [])
    for body in ({"name": "copy", "copy_from": env_id}, {"name": "child", "parent_id": env_id}):
        res = await client.post(
            f"/api/projects/{project_id}/environments", headers=keeper, json=body
        )
        # Проект ему не выдан вовсе: для него проекта нет (как и в списке).
        assert res.status_code == 404, res.text
    names = [
        e["name"]
        for e in (
            await client.get(f"/api/projects/{project_id}/environments", headers=owner_headers)
        ).json()
    ]
    assert "copy" not in names and "child" not in names


async def test_idle_counts_reads_through_children_and_colons(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Ключ base, который читают стенды-наследники, - не кандидат на удаление.
    Двоеточие в папке не сбивает сверку с журналом."""
    project_id = await _project(client, owner_headers)
    base = await _env(client, owner_headers, project_id, "tech-base")
    tech1 = await _env(client, owner_headers, project_id, "tech1", parent_id=base)
    assert (await _put(client, owner_headers, base, "SMTP_HOST", "smtp.local")).status_code == 200
    assert (await _put(client, owner_headers, base, "UNUSED", "x")).status_code == 200
    assert (await _put(client, owner_headers, base, "PORT", "1", path="/x:y")).status_code == 200

    assert (await _value(client, owner_headers, tech1, "SMTP_HOST")).status_code == 200
    assert (await _value(client, owner_headers, base, "PORT", path="/x:y")).status_code == 200

    idle = await client.get(f"/api/environments/{base}/idle", headers=owner_headers)
    assert idle.status_code == 200, idle.text
    names = {(row["path"], row["name"]) for row in idle.json()["rows"]}
    assert names == {("/", "UNUSED")}

    events = await client.get(f"/api/environments/{base}/events", headers=owner_headers)
    keys = {row["key"] for row in events.json() if row["action"] == "secret_read"}
    assert "/x:y/PORT" in keys
