"""История, откат, переименование, обмен .env и снимки окружения."""

import httpx

from tests.conftest import login


async def _put(client, headers, env_id, name, value, path="/"):
    return await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )


async def _value(client, headers, env_id, name, path="/"):
    res = await client.get(
        f"/api/environments/{env_id}/secret",
        headers=headers,
        params={"name": name, "path": path},
    )
    return res


async def test_history_lists_every_version_without_values(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "TOKEN", "first")
    await _put(client, owner_headers, env_id, "TOKEN", "second")
    res = await client.get(
        f"/api/environments/{env_id}/secret/history",
        headers=owner_headers,
        params={"name": "TOKEN"},
    )
    assert res.status_code == 200
    rows = res.json()
    assert [r["version"] for r in rows] == [2, 1]
    assert rows[0]["current"] is True
    # в истории нет ни одного значения - её смотрят и те, кому нельзя читать
    assert "first" not in res.text and "second" not in res.text


async def test_old_version_can_be_read_and_is_logged(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "TOKEN", "first")
    await _put(client, owner_headers, env_id, "TOKEN", "second")
    res = await client.get(
        f"/api/environments/{env_id}/secret/version",
        headers=owner_headers,
        params={"name": "TOKEN", "version": 1},
    )
    assert res.status_code == 200
    assert res.json()["value"] == "first"

    log = await client.get("/api/audit", headers=owner_headers)
    assert "secret_version_read" in [e["action"] for e in log.json()["entries"]]
    assert "first" not in log.text


async def test_rollback_creates_a_new_version(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "TOKEN", "first")
    await _put(client, owner_headers, env_id, "TOKEN", "second")
    res = await client.post(
        f"/api/environments/{env_id}/secret/rollback",
        headers=owner_headers,
        json={"name": "TOKEN", "version": 1},
    )
    assert res.status_code == 200
    assert res.json()["version"] == 3  # именно новая версия, а не воскресшая старая
    assert (await _value(client, owner_headers, env_id, "TOKEN")).json()["value"] == "first"

    history = await client.get(
        f"/api/environments/{env_id}/secret/history",
        headers=owner_headers,
        params={"name": "TOKEN"},
    )
    # то, что откатили, осталось в истории
    assert [r["version"] for r in history.json()] == [3, 2, 1]


async def test_rename_keeps_the_value_and_frees_the_old_name(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "OLD_NAME", "секрет")
    res = await client.post(
        f"/api/environments/{env_id}/secret/rename",
        headers=owner_headers,
        json={"name": "OLD_NAME", "new_name": "NEW_NAME"},
    )
    assert res.status_code == 200, res.text
    assert (await _value(client, owner_headers, env_id, "NEW_NAME")).json()["value"] == "секрет"
    assert (await _value(client, owner_headers, env_id, "OLD_NAME")).status_code == 404
    # старое имя осталось в истории: по журналу видно, чем ключ был раньше
    history = await client.get(
        f"/api/environments/{env_id}/secret/history",
        headers=owner_headers,
        params={"name": "NEW_NAME"},
    )
    assert {r["name"] for r in history.json()} == {"OLD_NAME", "NEW_NAME"}


async def test_rename_refuses_to_shadow_existing_key(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "A", "one")
    await _put(client, owner_headers, env_id, "B", "two")
    res = await client.post(
        f"/api/environments/{env_id}/secret/rename",
        headers=owner_headers,
        json={"name": "A", "new_name": "B"},
    )
    assert res.status_code == 409


async def test_export_import_round_trip(client: httpx.AsyncClient, owner_headers, env_id):
    """Выгруженное окружение должно читаться обратно ровно тем же - иначе перенос
    между стендами тихо портит значения с пробелами и переносами."""
    values = {
        "SIMPLE": "value",
        "WITH_SPACES": "два слова",
        "WITH_HASH": "pa#ss",
        "WITH_QUOTE": 'ка"выч',
        "MULTILINE": "-----BEGIN KEY-----\nabc\n-----END KEY-----",
        "EMPTY": "",
    }
    for name, value in values.items():
        assert (await _put(client, owner_headers, env_id, name, value)).status_code == 200

    dump = await client.get(f"/api/environments/{env_id}/export", headers=owner_headers)
    assert dump.status_code == 200
    text = dump.json()["text"]

    # заводим второе окружение и заливаем туда выгрузку
    projects = await client.get("/api/projects", headers=owner_headers)
    project_id = projects.json()[0]["id"]
    second = await client.post(
        f"/api/projects/{project_id}/environments",
        headers=owner_headers,
        json={"name": "stage"},
    )
    second_id = second.json()["id"]
    res = await client.post(
        f"/api/environments/{second_id}/import", headers=owner_headers, json={"text": text}
    )
    assert res.status_code == 200, res.text
    assert res.json()["created"] == len(values)

    for name, value in values.items():
        got = await _value(client, owner_headers, second_id, name)
        assert got.status_code == 200, (name, got.text)
        assert got.json()["value"] == value, name


async def test_import_does_not_overwrite_by_default(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "KEEP", "живое значение")
    res = await client.post(
        f"/api/environments/{env_id}/import",
        headers=owner_headers,
        json={"text": "KEEP=чужое значение\nNEW=свежее"},
    )
    assert res.json()["skipped"] == ["KEEP"]
    assert res.json()["created"] == 1
    assert (await _value(client, owner_headers, env_id, "KEEP")).json()["value"] == "живое значение"

    res = await client.post(
        f"/api/environments/{env_id}/import",
        headers=owner_headers,
        json={"text": "KEEP=чужое значение", "overwrite": True},
    )
    assert res.json()["updated"] == 1
    assert (await _value(client, owner_headers, env_id, "KEEP")).json()["value"] == "чужое значение"


async def test_broken_import_changes_nothing(client: httpx.AsyncClient, owner_headers, env_id):
    """Половина импортированного файла хуже, чем ни одной строки."""
    res = await client.post(
        f"/api/environments/{env_id}/import",
        headers=owner_headers,
        json={"text": "GOOD=1\nэто не переменная\nALSO_GOOD=2"},
    )
    assert res.status_code == 400
    listed = await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    assert listed.json() == []


async def test_snapshot_restores_state(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "A", "было")
    snap = await client.post(
        f"/api/environments/{env_id}/snapshots",
        headers=owner_headers,
        json={"name": "перед релизом"},
    )
    assert snap.status_code == 201, snap.text
    snapshot_id = snap.json()["id"]
    assert snap.json()["keys"] == 1

    await _put(client, owner_headers, env_id, "A", "стало")
    await _put(client, owner_headers, env_id, "B", "новый ключ")

    plan = await client.get(
        f"/api/environments/{env_id}/snapshots/{snapshot_id}/plan", headers=owner_headers
    )
    actions = {(r["name"], r["action"]) for r in plan.json()}
    assert ("A", "вернуть версию 1") in actions
    assert ("B", "удалить") in actions

    res = await client.post(
        f"/api/environments/{env_id}/snapshots/{snapshot_id}/restore", headers=owner_headers
    )
    assert res.json() == {"restored": 1, "removed": 1}
    assert (await _value(client, owner_headers, env_id, "A")).json()["value"] == "было"
    # ключ, заведенный после снимка, удален - но его историю можно поднять
    assert (await _value(client, owner_headers, env_id, "B")).status_code == 404
    history = await client.get(
        f"/api/environments/{env_id}/secret/history",
        headers=owner_headers,
        params={"name": "B"},
    )
    assert history.status_code == 200
    assert history.json()[0]["deleted"] is True


async def test_deleting_snapshot_keeps_history(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "A", "значение")
    snap = await client.post(
        f"/api/environments/{env_id}/snapshots", headers=owner_headers, json={"name": "точка"}
    )
    res = await client.delete(
        f"/api/environments/{env_id}/snapshots/{snap.json()['id']}", headers=owner_headers
    )
    assert res.status_code == 204
    assert (await _value(client, owner_headers, env_id, "A")).json()["value"] == "значение"


async def test_developer_sees_history_but_not_values(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "TOKEN", "секрет")
    dev_id = (
        await client.post(
            "/api/users",
            headers=owner_headers,
            json={"username": "dev", "password": "member-pass-2026", "role": "developer"},
        )
    ).json()["id"]
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={"subject_type": "user", "subject_id": dev_id, "actions": ["list"]},
    )
    dev = await login(client, "dev", "member-pass-2026")

    history = await client.get(
        f"/api/environments/{env_id}/secret/history", headers=dev, params={"name": "TOKEN"}
    )
    assert history.status_code == 200

    value = await client.get(
        f"/api/environments/{env_id}/secret/version",
        headers=dev,
        params={"name": "TOKEN", "version": 1},
    )
    assert value.status_code == 403
    assert (await client.get(f"/api/environments/{env_id}/export", headers=dev)).status_code == 403
    assert (
        await client.post(
            f"/api/environments/{env_id}/import", headers=dev, json={"text": "X=1"}
        )
    ).status_code == 403

async def test_project_export_collects_every_environment(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Проект целиком одним файлом: каждое окружение своим блоком.

    Выгрузка по одному стенду была и раньше, но проект на два десятка окружений
    так не собрать - а собирают его, когда проект переезжает.
    """
    project = (await client.get("/api/projects", headers=owner_headers)).json()[0]
    made = await client.post(
        f"/api/projects/{project['id']}/environments",
        headers=owner_headers,
        json={"name": "stage", "parent_id": None},
    )
    stage = made.json()["id"]
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "APP_ENV", "value": "production", "path": "/"},
    )
    await client.put(
        f"/api/environments/{stage}/secrets",
        headers=owner_headers,
        json={"name": "APP_ENV", "value": "stage", "path": "/"},
    )

    res = await client.get(f"/api/projects/{project['id']}/export", headers=owner_headers)
    assert res.status_code == 200, res.text
    text = res.json()["text"]
    assert res.json()["skipped"] == []
    assert text.count("# --- ") == 2
    assert "APP_ENV=production" in text
    assert "APP_ENV=stage" in text

    log = (await client.get("/api/audit", headers=owner_headers)).json()
    assert any(row["action"] == "project_exported" for row in log["entries"])
