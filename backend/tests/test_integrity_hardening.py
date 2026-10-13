"""Целостность значений: папки, наследование при импорте и копии, правка базы
в обход панели, журнал и напоминания. Найдено разбором перед выпуском 1.0.0."""

import httpx
from sqlalchemy import select, update

from app.models import AuditLog, LintSeen, Secret


async def _put(client, headers, env_id, name, value, path="/"):
    return await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )


def _state(client):
    return client._transport.app.state


async def _child(client, owner_headers, parent_id, name="stage") -> int:
    project_id = (await client.get("/api/projects", headers=owner_headers)).json()[0]["id"]
    res = await client.post(
        f"/api/projects/{project_id}/environments",
        headers=owner_headers,
        json={"name": name, "parent_id": parent_id},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def test_folders_that_export_cannot_hold_are_refused(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Выгрузка пишет папку меткой "# /путь" без пробелов: папка с пробелом или
    # при обратной заливке уезжала в соседнюю и перезаписывала чужой ключ."""
    for path in ("/db reporting", "/a#b", "/tab\there"):
        res = await _put(client, owner_headers, env_id, "K", "v", path=path)
        assert res.status_code == 400, f"{path!r}: {res.text}"
    await _put(client, owner_headers, env_id, "K", "v", path="/db")
    res = await client.post(
        f"/api/environments/{env_id}/secret/rename",
        headers=owner_headers,
        json={"name": "K", "path": "/db", "new_name": "K", "new_path": "/db x"},
    )
    assert res.status_code in (400, 409), res.text


async def test_import_without_overwrite_keeps_inherited_values(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "SHARED", "from-parent")
    child = await _child(client, owner_headers, env_id)
    res = await client.post(
        f"/api/environments/{child}/import",
        headers=owner_headers,
        json={"text": "SHARED=from-file\nNEW=1\n"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["skipped"] == ["SHARED"]
    value = await client.get(
        f"/api/environments/{child}/secret", headers=owner_headers, params={"name": "SHARED"}
    )
    assert value.json()["value"] == "from-parent"


async def test_copy_from_takes_an_inherited_value(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Список недостающих ключей предлагает окружение, где ключ унаследован, -
    копия оттуда должна работать, а не отвечать 404."""
    await _put(client, owner_headers, env_id, "SMTP_HOST", "smtp.example")
    child = await _child(client, owner_headers, env_id, "tech1")
    other = await _child(client, owner_headers, None, "other")
    res = await client.post(
        f"/api/environments/{other}/copy-from",
        headers=owner_headers,
        json={"source": "tech1", "name": "SMTP_HOST", "path": "/"},
    )
    assert res.status_code == 200, res.text
    assert child


async def test_e2e_needs_a_project_without_any_history(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Удаленный ключ хранит открытые значения в истории: откат вернул бы их в
    проект, где сервер не должен видеть открытого текста."""
    await _put(client, owner_headers, env_id, "OLD", "plain")
    await client.delete(f"/api/environments/{env_id}/secret", headers=owner_headers, params={"name": "OLD"})
    project_id = (await client.get("/api/projects", headers=owner_headers)).json()[0]["id"]
    nonce = "AAAAAAAAAAAAAAAA"  # 12 байт
    res = await client.post(
        f"/api/projects/{project_id}/e2e",
        headers=owner_headers,
        json={"nonce": nonce, "wrapped_key": "A" * 64, "verifier_nonce": nonce, "verifier": "A" * 64, "salt": "A" * 24},
    )
    assert res.status_code == 400, res.text


def test_wrap_nonce_must_be_twelve_bytes():
    import pytest

    from app import e2e

    e2e.check_wrap("AAAAAAAAAAAAAAAA", "AAAA")
    with pytest.raises(e2e.FormatError):
        e2e.check_wrap("AAAAAAAAAAAA", "AAAA")  # 9 байт: агент на Go упал бы паникой


async def test_names_swapped_in_the_database_are_noticed(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Поменять местами имена двух ключей правкой таблицы: раньше панель
    отдавала пароль базы под именем баннера, теперь чтение отказывает."""
    await _put(client, owner_headers, env_id, "DB_PASSWORD", "secret")
    await _put(client, owner_headers, env_id, "PUBLIC_BANNER", "hello")
    async with _state(client).session_factory() as session:
        rows = {s.name: s.id for s in await session.scalars(select(Secret))}
        await session.execute(update(Secret).where(Secret.id == rows["DB_PASSWORD"]).values(name="TMP"))
        await session.execute(update(Secret).where(Secret.id == rows["PUBLIC_BANNER"]).values(name="DB_PASSWORD"))
        await session.execute(update(Secret).where(Secret.id == rows["DB_PASSWORD"]).values(name="PUBLIC_BANNER"))
        await session.commit()
    res = await client.get(
        f"/api/environments/{env_id}/secret", headers=owner_headers, params={"name": "DB_PASSWORD"}
    )
    assert res.status_code == 500
    assert "hello" not in res.text
    export = await client.get(f"/api/environments/{env_id}/export", headers=owner_headers)
    assert export.status_code == 500


async def test_long_path_and_name_fit_the_audit_log(
    client: httpx.AsyncClient, owner_headers, env_id
):
    path = "/" + "p" * 190
    res = await _put(client, owner_headers, env_id, "N" * 190, "v", path=path)
    assert res.status_code == 200, res.text
    async with _state(client).session_factory() as session:
        targets = [row.target for row in await session.scalars(select(AuditLog))]
    assert max(len(t) for t in targets) <= 200


async def test_lint_sweep_keeps_expiry_marks(client: httpx.AsyncClient, owner_headers, env_id):
    """Обход замечаний стирал отметки о сроке, и напоминание о том же сроке
    приходило каждые шесть часов."""
    from app import lint_watch

    async with _state(client).session_factory() as session:
        session.add(LintSeen(environment_id=env_id, path="/", name="TOKEN", code=lint_watch.EXPIRY_CODE))
        await session.commit()
    await lint_watch.sweep(_state(client).session_factory, _state(client).sealbox)
    async with _state(client).session_factory() as session:
        left = list(await session.scalars(select(LintSeen).where(LintSeen.code == lint_watch.EXPIRY_CODE)))
    assert len(left) == 1
