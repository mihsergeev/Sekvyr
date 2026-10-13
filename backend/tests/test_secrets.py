"""Секреты: что попадает в базу, кто что видит, как живут версии."""

import httpx
from sqlalchemy import select

from app.config import get_settings
from app.db import create_engine_and_factory
from app.models import SecretVersion
from tests.conftest import login

VALUE = "sup3r-prod-password"


async def _put(client, headers, env_id, name, value, path="/"):
    return await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )


async def _get(client, headers, env_id, name, path="/"):
    return await client.get(
        f"/api/environments/{env_id}/secret",
        headers=headers,
        params={"name": name, "path": path},
    )


async def _versions() -> list[SecretVersion]:
    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        rows = list(await session.scalars(select(SecretVersion)))
    await engine.dispose()
    return rows


async def test_write_and_read(client: httpx.AsyncClient, owner_headers, env_id):
    assert (await _put(client, owner_headers, env_id, "DB_PASSWORD", VALUE)).status_code == 200
    res = await _get(client, owner_headers, env_id, "DB_PASSWORD")
    assert res.status_code == 200
    assert res.json()["value"] == VALUE
    assert res.json()["version"] == 1


async def test_database_holds_only_ciphertext(client: httpx.AsyncClient, owner_headers, env_id):
    """Главное свойство всей затеи: в базе значения нет ни в каком виде."""
    await _put(client, owner_headers, env_id, "DB_PASSWORD", VALUE)
    rows = await _versions()
    assert rows
    for row in rows:
        assert VALUE not in row.ciphertext
        assert VALUE not in row.nonce
        assert VALUE not in (row.comment or "")


async def test_value_cannot_be_moved_between_secrets(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Подмена строки в базе: берем шифротекст одного ключа и кладем в другой.
    Значение не должно прочитаться - иначе прод-пароль подменяется правкой SQL."""
    await _put(client, owner_headers, env_id, "DB_PASSWORD", VALUE)
    await _put(client, owner_headers, env_id, "SMTP_PASSWORD", "smtp-value")

    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        rows = {r.name_at: r for r in await session.scalars(select(SecretVersion))}
        source, target = rows["DB_PASSWORD"], rows["SMTP_PASSWORD"]
        target.nonce, target.ciphertext = source.nonce, source.ciphertext
        await session.commit()
    await engine.dispose()

    res = await _get(client, owner_headers, env_id, "SMTP_PASSWORD")
    assert res.status_code == 500
    assert "в обход панели" in res.json()["detail"]


async def test_new_write_makes_a_new_version(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "TOKEN", "first")
    await _put(client, owner_headers, env_id, "TOKEN", "second")
    res = await _get(client, owner_headers, env_id, "TOKEN")
    assert res.json()["value"] == "second"
    assert res.json()["version"] == 2
    # прежняя версия никуда не делась - на ней будет стоять откат в M2
    rows = await _versions()
    assert sorted(r.version for r in rows) == [1, 2]
    assert {r.status for r in rows} == {"superseded", "current"}


async def test_delete_is_reversible_by_history(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "TOKEN", "value")
    res = await client.delete(
        f"/api/environments/{env_id}/secret", headers=owner_headers, params={"name": "TOKEN"}
    )
    assert res.status_code == 204
    assert (await _get(client, owner_headers, env_id, "TOKEN")).status_code == 404
    listed = await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    assert listed.json() == []
    # история осталась: удаление - это версия, а не стирание
    rows = await _versions()
    assert len(rows) == 2
    assert rows[-1].deleted is True


async def test_paths_are_normalised(client: httpx.AsyncClient, owner_headers, env_id):
    """"/db", "/db/" и "db" - один каталог, иначе в окружении заводятся три
    одинаковых ключа, и человек читает не тот."""
    await _put(client, owner_headers, env_id, "PASS", "one", path="/db")
    await _put(client, owner_headers, env_id, "PASS", "two", path="db/")
    listed = await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    assert len(listed.json()) == 1
    assert listed.json()[0]["path"] == "/db"
    assert (await _get(client, owner_headers, env_id, "PASS", path="/db")).json()["value"] == "two"


async def test_list_shows_names_but_not_values(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "DB_PASSWORD", VALUE)
    res = await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    assert res.status_code == 200
    assert VALUE not in res.text
    assert res.json()[0]["name"] == "DB_PASSWORD"


async def test_developer_sees_the_list_but_not_the_value(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Ради этого разделения `list` и `read` вообще существуют."""
    await _put(client, owner_headers, env_id, "DB_PASSWORD", VALUE)
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
    listed = await client.get(f"/api/environments/{env_id}/secrets", headers=dev)
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "DB_PASSWORD"
    assert (await _get(client, dev, env_id, "DB_PASSWORD")).status_code == 403


async def test_reads_are_recorded(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "DB_PASSWORD", VALUE)
    await _get(client, owner_headers, env_id, "DB_PASSWORD")
    log = await client.get("/api/audit", headers=owner_headers)
    actions = [e["action"] for e in log.json()["entries"]]
    assert "secret_read" in actions
    assert "secret_written" in actions
    # и значение в журнал не просочилось
    assert VALUE not in log.text


async def test_sealed_panel_gives_nothing(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "DB_PASSWORD", VALUE)
    await client.post("/api/vault/seal", headers=owner_headers)

    read = await _get(client, owner_headers, env_id, "DB_PASSWORD")
    assert read.status_code == 503
    write = await _put(client, owner_headers, env_id, "OTHER", "x")
    assert write.status_code == 503
    # список ключей при этом виден: он не требует расшифровки
    assert (await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)).status_code == 200


async def test_env_key_rotation_reencrypts_everything(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "A", "one")
    await _put(client, owner_headers, env_id, "A", "two")
    await _put(client, owner_headers, env_id, "B", "three")
    before = {r.id: r.ciphertext for r in await _versions()}

    res = await client.post(f"/api/environments/{env_id}/rotate-key", headers=owner_headers)
    assert res.status_code == 200, res.text
    assert res.json()["key_generation"] == 2
    assert res.json()["reencrypted_versions"] == 3

    after = {r.id: r.ciphertext for r in await _versions()}
    assert all(before[i] != after[i] for i in before)  # все перешифровано
    assert (await _get(client, owner_headers, env_id, "A")).json()["value"] == "two"
    assert (await _get(client, owner_headers, env_id, "B")).json()["value"] == "three"


async def test_all_values_come_as_structure(client, owner_headers, env_id):
    """Окно "Редактировать все" получает значения структурой, а не текстом.

    В тексте .env значение в несколько строк экранируется, и разбирать его
    обратно в интерфейсе - лишний способ испортить конфиг.
    """
    config = "<?php\nreturn [\n    'debug' => true,\n];\n"
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "params.php", "path": "/php", "value": config},
    )
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_HOST", "value": "pg.internal"},
    )

    res = await client.get(f"/api/environments/{env_id}/values", headers=owner_headers)
    assert res.status_code == 200, res.text
    values = {(row["path"], row["name"]): row["value"] for row in res.json()}
    assert values[("/php", "params.php")] == config
    assert values[("/", "DB_HOST")] == "pg.internal"


async def test_export_names_a_folder_once(client, owner_headers, env_id):
    """Сотня строк "# /infra" подряд - это не структура, а помеха чтению."""
    for name in ("DB_HOST", "DB_NAME", "DB_USER"):
        await client.put(
            f"/api/environments/{env_id}/secrets",
            headers=owner_headers,
            json={"name": name, "path": "/infra", "value": "x"},
        )
    text = (await client.get(f"/api/environments/{env_id}/export", headers=owner_headers)).json()["text"]
    assert text.count("# /infra") == 1


async def test_multiline_value_survives_export_and_import(client, owner_headers, env_id):
    """Конфиг выгружается переносами как есть и возвращается таким же.

    Свернутый в одну строку с "\n" он нечитаем ровно там, где файл и нужен -
    в редакторе.
    """
    config = "<?php\nreturn [\n    'dsn' => 'pgsql:host=db',\n    'quote' => \"a\\\"b\",\n];\n"
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "main.php", "value": config},
    )
    text = (await client.get(f"/api/environments/{env_id}/export", headers=owner_headers)).json()["text"]
    assert "return [" in text.splitlines()[1], "перенос строки должен остаться переносом"

    # тот же текст, залитый обратно, дает то же значение
    other = await client.post(
        "/api/projects/1/environments", headers=owner_headers, json={"name": "copy"}
    )
    copy_id = other.json()["id"]
    res = await client.post(
        f"/api/environments/{copy_id}/import",
        headers=owner_headers,
        json={"text": text, "path": "/", "overwrite": True},
    )
    assert res.status_code == 200, res.text
    value = await client.get(
        f"/api/environments/{copy_id}/secret", headers=owner_headers, params={"name": "main.php"}
    )
    assert value.json()["value"] == config


async def test_import_puts_keys_back_into_their_folders(client, owner_headers, env_id):
    """Файл, скачанный отсюда, возвращается туда же, откуда взят.

    Иначе скачать и залить обратно означало бы свалить сотню ключей из пяти
    папок в корень и разбирать это руками.
    """
    for path, name in (("/", "APP_ENV"), ("/infra", "DB_HOST"), ("/external", "S3_KEY")):
        await client.put(
            f"/api/environments/{env_id}/secrets",
            headers=owner_headers,
            json={"name": name, "path": path, "value": f"{path}:{name}"},
        )
    text = (await client.get(f"/api/environments/{env_id}/export", headers=owner_headers)).json()["text"]

    other = await client.post(
        "/api/projects/1/environments", headers=owner_headers, json={"name": "landing"}
    )
    copy_id = other.json()["id"]
    res = await client.post(
        f"/api/environments/{copy_id}/import",
        headers=owner_headers,
        json={"text": text, "path": "/", "overwrite": True},
    )
    assert res.status_code == 200, res.text

    listed = (await client.get(f"/api/environments/{copy_id}/secrets", headers=owner_headers)).json()
    where = {(row["path"], row["name"]) for row in listed}
    assert ("/infra", "DB_HOST") in where
    assert ("/external", "S3_KEY") in where
    assert ("/", "APP_ENV") in where


async def test_import_without_marks_uses_the_chosen_folder(client, owner_headers, env_id):
    """Чужой файл без пометок ложится туда, куда попросили в окне."""
    res = await client.post(
        f"/api/environments/{env_id}/import",
        headers=owner_headers,
        json={"text": "A=1\nB=2\n", "path": "/vendor", "overwrite": True},
    )
    assert res.status_code == 200, res.text
    listed = (await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)).json()
    assert {row["path"] for row in listed if row["name"] in ("A", "B")} == {"/vendor"}

async def test_diff_shows_difference_without_values(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Сравнение отвечает "где разное", не показывая значений.

    Ради этого оно и нужно: "почему на stage работает, а на проде нет" - вопрос
    про разницу, и ответ на него не должен требовать чтения обоих окружений
    глазами.
    """
    project = (await client.get("/api/projects", headers=owner_headers)).json()[0]
    other = await client.post(
        f"/api/projects/{project['id']}/environments",
        headers=owner_headers,
        json={"name": "stage", "parent_id": None},
    )
    assert other.status_code == 201, other.text
    stage = other.json()["id"]

    async def put(env, name, value):
        res = await client.put(
            f"/api/environments/{env}/secrets",
            headers=owner_headers,
            json={"name": name, "value": value, "path": "/"},
        )
        assert res.status_code == 200, res.text

    await put(env_id, "APP_ENV", "production")
    await put(stage, "APP_ENV", "stage")
    await put(env_id, "SHARED", "одинаково")
    await put(stage, "SHARED", "одинаково")
    await put(env_id, "ONLY_PROD", "есть только здесь")
    await put(stage, "ONLY_STAGE", "есть только там")

    res = await client.get(
        f"/api/environments/{env_id}/diff", headers=owner_headers, params={"other": stage}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["other"] == "stage"
    assert body["same"] == 1
    states = {row["name"]: row["state"] for row in body["rows"]}
    assert states == {
        "APP_ENV": "differs",
        "ONLY_PROD": "here",
        "ONLY_STAGE": "there",
    }
    # Значений в ответе нет ни в каком виде.
    assert "production" not in res.text
    assert "одинаково" not in res.text

    # И само сравнение осталось в журнале: панель читала значения.
    log = (await client.get("/api/audit", headers=owner_headers)).json()
    assert any(row["action"] == "env_compared" for row in log["entries"])


async def test_diff_refuses_another_project(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Сравнивать можно только стенды одного проекта: иначе это не разница, а
    список чужих ключей."""
    made = await client.post(
        "/api/projects",
        headers=owner_headers,
        json={"slug": "other-project", "title": "", "group_name": "", "environments": ["prod"]},
    )
    assert made.status_code == 201, made.text
    envs = (
        await client.get(
            f"/api/projects/{made.json()['id']}/environments", headers=owner_headers
        )
    ).json()
    res = await client.get(
        f"/api/environments/{env_id}/diff",
        headers=owner_headers,
        params={"other": envs[0]["id"]},
    )
    assert res.status_code == 400

async def test_spread_writes_into_chosen_environments(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Раскладка пишет туда, где просили, и молчит там, где значение уже такое.

    Смысл ровно в этом: один токен в двадцати стендах вносят руками двадцать раз,
    а история при этом не должна пухнуть от повторных записей того же самого.
    """
    project = (await client.get("/api/projects", headers=owner_headers)).json()[0]
    names = ["stage", "qa"]
    made = []
    for name in names:
        res = await client.post(
            f"/api/projects/{project['id']}/environments",
            headers=owner_headers,
            json={"name": name, "parent_id": None},
        )
        assert res.status_code == 201, res.text
        made.append(res.json()["id"])

    put = await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "TELEGRAM_TOKEN", "value": "1234:abc", "path": "/"},
    )
    assert put.status_code == 200, put.text

    first = await client.post(
        f"/api/environments/{env_id}/spread",
        headers=owner_headers,
        json={"name": "TELEGRAM_TOKEN", "path": "/", "targets": made},
    )
    assert first.status_code == 200, first.text
    assert {row["environment"]: row["state"] for row in first.json()["rows"]} == {
        "stage": "written",
        "qa": "written",
    }

    value = await client.get(
        f"/api/environments/{made[0]}/secret",
        headers=owner_headers,
        params={"name": "TELEGRAM_TOKEN", "path": "/"},
    )
    assert value.json()["value"] == "1234:abc"

    again = await client.post(
        f"/api/environments/{env_id}/spread",
        headers=owner_headers,
        json={"name": "TELEGRAM_TOKEN", "path": "/", "targets": made},
    )
    assert {row["state"] for row in again.json()["rows"]} == {"same"}
    # Второй записи не появилось: версия осталась первой.
    history = await client.get(
        f"/api/environments/{made[0]}/secret/history",
        headers=owner_headers,
        params={"name": "TELEGRAM_TOKEN", "path": "/"},
    )
    assert len(history.json()) == 1


async def test_spread_ignores_other_projects(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Чужое окружение в списке целей просто пропускается: раскладка - про
    стенды одного проекта, а не про панель целиком."""
    made = await client.post(
        "/api/projects",
        headers=owner_headers,
        json={"slug": "neighbour", "title": "", "group_name": "", "environments": ["prod"]},
    )
    assert made.status_code == 201, made.text
    foreign = (
        await client.get(
            f"/api/projects/{made.json()['id']}/environments", headers=owner_headers
        )
    ).json()[0]["id"]

    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "SHARED", "value": "тут", "path": "/"},
    )
    res = await client.post(
        f"/api/environments/{env_id}/spread",
        headers=owner_headers,
        json={"name": "SHARED", "path": "/", "targets": [foreign]},
    )
    assert res.status_code == 200
    assert res.json()["rows"] == []
    listed = await client.get(f"/api/environments/{foreign}/secrets", headers=owner_headers)
    assert listed.json() == []

async def test_rename_can_follow_all_environments(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Имя ключа - общий словарь проекта, и переименовать его можно везде разом.

    Там, где ключа нет, ничего не появляется: раскладка имен - не способ завести
    ключ на чужом стенде.
    """
    project = (await client.get("/api/projects", headers=owner_headers)).json()[0]
    made = {}
    for name in ("stage", "qa"):
        res = await client.post(
            f"/api/projects/{project['id']}/environments",
            headers=owner_headers,
            json={"name": name, "parent_id": None},
        )
        made[name] = res.json()["id"]

    for env in (env_id, made["stage"]):
        await client.put(
            f"/api/environments/{env}/secrets",
            headers=owner_headers,
            json={"name": "OLD_NAME", "value": "значение", "path": "/"},
        )

    res = await client.post(
        f"/api/environments/{env_id}/secret/rename",
        headers=owner_headers,
        json={
            "name": "OLD_NAME",
            "path": "/",
            "new_name": "NEW_NAME",
            "new_path": "/",
            "everywhere": True,
        },
    )
    assert res.status_code == 200, res.text
    assert res.json()["also_renamed"] == ["stage"]

    here = await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    assert {row["name"] for row in here.json()} == {"NEW_NAME"}
    stage = await client.get(
        f"/api/environments/{made['stage']}/secrets", headers=owner_headers
    )
    assert {row["name"] for row in stage.json()} == {"NEW_NAME"}
    empty = await client.get(f"/api/environments/{made['qa']}/secrets", headers=owner_headers)
    assert empty.json() == []


async def test_secret_note_and_expiry(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Подпись и срок живут у ключа и значения не касаются."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "BOT_TOKEN", "value": "1234:abc", "path": "/"},
    )
    res = await client.post(
        f"/api/environments/{env_id}/secret/meta",
        headers=owner_headers,
        json={
            "name": "BOT_TOKEN",
            "path": "/",
            "note": "токен бота оповещений",
            "expires_at": "2027-03-01",
        },
    )
    assert res.status_code == 200, res.text
    assert res.json()["note"] == "токен бота оповещений"
    assert res.json()["expires_at"].startswith("2027-03-01")

    listed = (
        await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    ).json()
    row = [r for r in listed if r["name"] == "BOT_TOKEN"][0]
    assert row["note"] == "токен бота оповещений"
    # Версия осталась прежней: подпись - не правка значения.
    assert row["version"] == 1

    bad = await client.post(
        f"/api/environments/{env_id}/secret/meta",
        headers=owner_headers,
        json={"name": "BOT_TOKEN", "path": "/", "note": "", "expires_at": "первое марта"},
    )
    assert bad.status_code == 400

async def test_same_value_finds_places_not_values(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Где еще лежит такое же значение: ответ - места, а не значение.

    Вопрос задают при компрометации, и перебор двух сотен окружений глазами -
    это работа на день.
    """
    project = (await client.get("/api/projects", headers=owner_headers)).json()[0]
    made = await client.post(
        f"/api/projects/{project['id']}/environments",
        headers=owner_headers,
        json={"name": "stage", "parent_id": None},
    )
    stage = made.json()["id"]

    for env in (env_id, stage):
        await client.put(
            f"/api/environments/{env}/secrets",
            headers=owner_headers,
            json={"name": "SHARED", "value": "один-и-тот-же", "path": "/"},
        )
    await client.put(
        f"/api/environments/{stage}/secrets",
        headers=owner_headers,
        json={"name": "OTHER", "value": "другое", "path": "/"},
    )

    res = await client.get(
        f"/api/environments/{env_id}/same",
        headers=owner_headers,
        params={"name": "SHARED", "path": "/"},
    )
    assert res.status_code == 200, res.text
    assert [(row["environment"], row["name"]) for row in res.json()] == [("stage", "SHARED")]
    # Самого значения в ответе нет ни в каком виде.
    assert "один-и-тот-же" not in res.text


async def test_who_sees_lists_grants(client: httpx.AsyncClient, owner_headers, env_id):
    """"Кому это видно" собирает права этого стенда и права на весь проект."""
    made = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "ivan", "password": "длинный-пароль-1234", "role": "developer"},
    )
    user_id = made.json()["id"]
    granted = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "user",
            "subject_id": user_id,
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": ["list", "read"],
            "effect": "allow",
        },
    )
    assert granted.status_code == 201, granted.text

    res = await client.get(f"/api/environments/{env_id}/who", headers=owner_headers)
    assert res.status_code == 200, res.text
    rows = res.json()
    assert [row["subject"] for row in rows] == ["ivan"]
    assert rows[0]["actions"] == ["list", "read"]
    assert rows[0]["whole_project"] is False


async def test_spread_does_not_tell_equality_without_read_right(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """С правом только писать в соседнее окружение "уже такое же" отвечало бы
    на вопрос, совпадает ли чужое значение с моим. Такому человеку раскладка
    просто пишет, не сравнивая."""
    project = (await client.get("/api/projects", headers=owner_headers)).json()[0]
    res = await client.post(
        f"/api/projects/{project['id']}/environments",
        headers=owner_headers,
        json={"name": "stage", "parent_id": None},
    )
    stage = res.json()["id"]
    for target in (env_id, stage):
        await client.put(
            f"/api/environments/{target}/secrets",
            headers=owner_headers,
            json={"name": "TELEGRAM_TOKEN", "value": "1234:abc", "path": "/"},
        )
    user = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "writer", "password": "writer-pass-2026", "role": "developer"},
    )
    for target, actions in ((env_id, ["list", "read"]), (stage, ["list", "write"])):
        await client.post(
            "/api/policies",
            headers=owner_headers,
            json={
                "subject_type": "user",
                "subject_id": user.json()["id"],
                "environment_id": target,
                "path_prefix": "/",
                "actions": actions,
                "effect": "allow",
            },
        )
    writer = await login(client, "writer", "writer-pass-2026")
    res = await client.post(
        f"/api/environments/{env_id}/spread",
        headers=writer,
        json={"name": "TELEGRAM_TOKEN", "path": "/", "targets": [stage]},
    )
    assert res.status_code == 200, res.text
    assert [row["state"] for row in res.json()["rows"]] == ["written"]
