"""Имя проекта живет внутри группы.

`frontend` бывает и у globex, и у initech. Пока имя было уникально на всю
панель, второй проект приходилось называть "initech-frontend" - то есть держать
группу в имени дважды.
"""

import httpx

from app.naming import slugify


async def _create(client, headers, slug, group="", environments=None):
    return await client.post(
        "/api/projects",
        headers=headers,
        json={
            "slug": slug,
            "title": "",
            "group_name": group,
            "environments": environments or [],
        },
    )


async def test_same_name_in_different_groups(client: httpx.AsyncClient, owner_headers):
    first = await _create(client, owner_headers, "frontend", "globex")
    second = await _create(client, owner_headers, "frontend", "initech")
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["group_slug"] == "globex"
    assert second.json()["group_slug"] == "initech"


async def test_same_name_in_one_group_is_refused(client: httpx.AsyncClient, owner_headers):
    await _create(client, owner_headers, "frontend", "globex")
    again = await _create(client, owner_headers, "frontend", "globex")
    assert again.status_code == 409
    assert "группе" in again.json()["detail"]


async def test_group_name_becomes_address(client: httpx.AsyncClient, owner_headers):
    """Группу называют по-русски, а в адресе нужен латинский кусок."""
    created = await _create(client, owner_headers, "api", "Биллинг и счета")
    assert created.json()["group_slug"] == "billing-i-scheta"
    assert slugify("Внутренние сервисы") == "vnutrennie-servisy"
    assert slugify("  ??? ") == ""


async def test_environments_are_created_with_the_project(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    created = await _create(
        client, owner_headers, "shop", "Магазин", ["prod", "stage", "dev"]
    )
    assert created.status_code == 201, created.text
    assert created.json()["environments"] == ["prod", "stage", "dev"]

    envs = await client.get(
        f"/api/projects/{created.json()['id']}/environments", headers=owner_headers
    )
    assert [e["name"] for e in envs.json()] == ["prod", "stage", "dev"]

    # Ключ окружения заводится сразу: окружение без ключа - это окружение, в
    # которое нельзя ничего записать, и проверяется это записью, а не полем.
    written = await client.put(
        f"/api/environments/{envs.json()[0]['id']}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "секрет"},
    )
    assert written.status_code == 200, written.text


async def test_repeated_environment_is_refused(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    created = await _create(client, owner_headers, "shop", "Магазин", ["prod", "prod"])
    assert created.status_code == 400


async def test_moving_to_a_taken_group_is_refused(client: httpx.AsyncClient, owner_headers):
    first = await _create(client, owner_headers, "frontend", "globex")
    second = await _create(client, owner_headers, "frontend", "initech")
    moved = await client.patch(
        f"/api/projects/{second.json()['id']}",
        headers=owner_headers,
        json={"group_name": "globex"},
    )
    assert moved.status_code == 409
    # Первый проект от неудачного переезда пострадать не должен.
    listed = await client.get("/api/projects", headers=owner_headers)
    assert [p for p in listed.json() if p["id"] == first.json()["id"]][0]["group_slug"] == (
        "globex"
    )


async def test_group_keeps_one_spelling(client: httpx.AsyncClient, owner_headers):
    """"globex" и "Globex" дают один кусок адреса, значит это одна группа.

    Разное написание рисовало в списке два одинаковых заголовка, между которыми
    нет никакой разницы.
    """
    await _create(client, owner_headers, "backend", "globex")
    joined = await _create(client, owner_headers, "frontend", "Globex")
    assert joined.json()["group_name"] == "globex"


async def test_renaming_a_group_moves_everyone(client: httpx.AsyncClient, owner_headers):
    first = await _create(client, owner_headers, "backend", "globex")
    second = await _create(client, owner_headers, "frontend", "globex")
    renamed = await client.patch(
        f"/api/projects/{second.json()['id']}",
        headers=owner_headers,
        json={"group_name": "Globex"},
    )
    assert renamed.status_code == 200, renamed.text

    listed = (await client.get("/api/projects", headers=owner_headers)).json()
    names = {p["group_name"] for p in listed if p["id"] in (first.json()["id"], second.json()["id"])}
    assert names == {"Globex"}
