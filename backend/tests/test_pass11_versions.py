"""Сохранение не перезаписывает молча чужую правку.

Двое открыли один ключ на правку, первый сохранил, второй сохранил поверх, и
правки первого в действующем значении больше нет, причем никто об этом не
узнал. Окно правки теперь присылает версию, от которой начинало, и сервер
отвечает 409, если она уже не действующая.
"""

from tests.conftest import client, env_id, owner_headers  # noqa: F401 - фикстуры

from app import secrets_store


async def _put(client, oh, env, value, **extra):
    body = {"name": "DATABASE_URL", "path": "/", "value": value, **extra}
    return await client.put(f"/api/environments/{env}/secrets", headers=oh, json=body)


async def _current(client, oh, env) -> tuple[int, str]:
    res = await client.get(
        f"/api/environments/{env}/secret", headers=oh, params={"name": "DATABASE_URL", "path": "/"}
    )
    assert res.status_code == 200, res.text
    return res.json()["version"], res.json()["value"]


async def test_stale_version_is_refused_and_keeps_the_newer_value(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "db-1")).status_code == 200
    seen, _ = await _current(client, oh, env_id)
    # Пока окно открыто, кто-то записал новую версию.
    assert (await _put(client, oh, env_id, "db-3")).status_code == 200
    res = await _put(client, oh, env_id, "db-2", expected_version=seen)
    assert res.status_code == 409, res.text
    body = res.json()
    assert body["conflict"] == "version"
    assert body["detail"] == secrets_store.KEY_CHANGED
    assert body["current_version"] == seen + 1
    assert await _current(client, oh, env_id) == (seen + 1, "db-3")


async def test_matching_version_saves_and_overwrite_is_explicit(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "db-1")).status_code == 200
    seen, _ = await _current(client, oh, env_id)
    res = await _put(client, oh, env_id, "db-2", expected_version=seen)
    assert res.status_code == 200, res.text
    assert res.json()["version"] == seen + 1
    # Осознанная перезапись - с той версией, которую человеку показали в 409.
    assert (await _put(client, oh, env_id, "db-x", expected_version=seen)).status_code == 409
    res = await _put(client, oh, env_id, "db-x", expected_version=seen + 1)
    assert res.status_code == 200, res.text


async def test_request_without_the_field_writes_as_before(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "db-1")).status_code == 200
    assert (await _put(client, oh, env_id, "db-2")).status_code == 200
    assert (await _current(client, oh, env_id))[1] == "db-2"


async def test_new_key_does_not_overwrite_one_created_meanwhile(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "theirs")).status_code == 200
    res = await _put(client, oh, env_id, "mine", expected_version=0)
    assert res.status_code == 409, res.text
    assert res.json()["detail"] == secrets_store.KEY_APPEARED
    assert (await _current(client, oh, env_id))[1] == "theirs"


async def test_key_deleted_meanwhile(client, owner_headers, env_id):
    oh = owner_headers
    assert (await _put(client, oh, env_id, "db-1")).status_code == 200
    seen, _ = await _current(client, oh, env_id)
    res = await client.delete(
        f"/api/environments/{env_id}/secret", headers=oh, params={"name": "DATABASE_URL", "path": "/"}
    )
    assert res.status_code == 204, res.text
    res = await _put(client, oh, env_id, "db-2", expected_version=seen)
    assert res.status_code == 409, res.text
    assert res.json()["detail"] == secrets_store.KEY_GONE
    assert res.json()["current_version"] == 0
    # Заново завести удаленный ключ - это версия 0 "своего ключа нет".
    assert (await _put(client, oh, env_id, "db-2", expected_version=0)).status_code == 200


async def test_override_of_an_inherited_key_starts_from_zero(client, owner_headers, env_id):
    oh = owner_headers
    project = (await client.get("/api/projects", headers=oh)).json()[0]["id"]
    res = await client.post(
        f"/api/projects/{project}/environments", headers=oh, json={"name": "tech1", "parent_id": env_id}
    )
    assert res.status_code in (200, 201), res.text
    child = res.json()["id"]
    assert (await _put(client, oh, env_id, "parent-db")).status_code == 200
    # В дочернем своего ключа нет: правка унаследованного начинается с 0.
    assert (await _put(client, oh, child, "child-db", expected_version=0)).status_code == 200
    assert (await _put(client, oh, child, "again", expected_version=0)).status_code == 409


async def test_expected_version_out_of_range_is_a_422(client, owner_headers, env_id):
    res = await _put(client, owner_headers, env_id, "x", expected_version=2**31)
    assert res.status_code == 422, res.text
