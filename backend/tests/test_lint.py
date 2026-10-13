"""Замечания к значениям: что панель считает ошибкой, а что нет.

Главное здесь - не "находит ли", а "не находит ли лишнего": замечание, которое
человек привыкает пролистывать, хуже, чем его отсутствие.
"""

from datetime import datetime, timedelta, timezone

import httpx

from app import lint


async def _put(client, headers, env_id, name, value, path="/"):
    return await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )


def _texts(name: str, value: str, environment: str = "prod") -> list[str]:
    return [note.text for note in lint.inspect(name, "/", value, environment)]


def test_trailing_space_is_an_error():
    assert _texts("DB_PASSWORD", "secret-value ") == [
        "значение начинается или кончается пробелом"
    ]


def test_placeholder_is_an_error():
    assert "это заготовка, а не значение" in _texts("API_TOKEN", "changeme")


def test_empty_secret_is_an_error():
    assert "пусто, хотя имя обещает секрет" in _texts("DB_PASSWORD", "")


def test_debug_on_production():
    assert "отладка включена на боевом окружении" in _texts("APP_DEBUG", "1")
    # То же значение на стенде - обычное дело и молчания не нарушает.
    assert _texts("APP_DEBUG", "1", environment="dev") == []


def test_localhost_on_production():
    assert "локальный адрес на боевом окружении" in _texts("DB_HOST", "localhost")
    assert _texts("DB_HOST", "localhost", environment="stage") == []


def test_test_key_on_production():
    assert "тестовый ключ на боевом окружении" in _texts("STRIPE_KEY", "sk_test_abc123def456")


def test_password_inside_url_is_normal():
    """Пароль в DSN - обычный формат, ради которого панель и заведена."""
    assert _texts("DATABASE_URL", "postgresql://app:hunter2@db.example.ru:5432/app") == []


def test_trailing_newline_in_a_file_is_normal():
    """Файл в значении кончается переводом строки - так и должно быть."""
    assert _texts("SERVICE_ACCOUNT", '{\n  "type": "service_account"\n}\n') == []


def test_http_outside():
    assert "адрес без шифрования: http вместо https" in _texts(
        "SENTRY_DSN", "http://key@sentry.example.ru/11"
    )
    # На локальный адрес это правило не распространяется: там http - норма.
    assert _texts("SENTRY_DSN", "http://localhost:9000/1", environment="dev") == []


def test_normal_values_are_silent():
    """Ради этого теста все и затевалось: обычные значения не должны мигать."""
    assert _texts("DB_HOST", "pg-prod.internal") == []
    assert _texts("APP_ENV", "production") == []
    assert _texts("DB_PASSWORD", "S3cur3-l0ng-passphrase") == []
    assert _texts("SENTRY_DSN", "https://key@sentry.example.ru/11") == []
    assert _texts("QUEUE_TTR", "300") == []


async def test_route_reports_notes(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "DB_PASSWORD", "changeme")
    await _put(client, owner_headers, env_id, "APP_ENV", "production")

    res = await client.get(f"/api/environments/{env_id}/lint", headers=owner_headers)
    assert res.status_code == 200, res.text
    notes = res.json()
    assert [n["name"] for n in notes] == ["DB_PASSWORD"]
    assert notes[0]["level"] == "bad"
    # Значение наружу не выходит - только замечание о нем.
    assert "changeme" not in res.text

async def test_muted_note_disappears(client: httpx.AsyncClient, owner_headers, env_id):
    """Принятое замечание больше не показывается, а возвращенное - снова да."""
    await _put(client, owner_headers, env_id, "LEGACY_URL", "http://legacy.example.ru/api")

    res = await client.get(f"/api/environments/{env_id}/lint", headers=owner_headers)
    assert [n["code"] for n in res.json()] == ["plain_http"]

    res = await client.post(
        f"/api/environments/{env_id}/lint/mute",
        headers=owner_headers,
        json={"name": "LEGACY_URL", "path": "/", "code": "plain_http"},
    )
    assert res.status_code == 204, res.text

    res = await client.get(f"/api/environments/{env_id}/lint", headers=owner_headers)
    assert res.json() == []

    # Второй раз то же принятие не должно ломаться: кнопку нажимают дважды.
    res = await client.post(
        f"/api/environments/{env_id}/lint/mute",
        headers=owner_headers,
        json={"name": "LEGACY_URL", "path": "/", "code": "plain_http"},
    )
    assert res.status_code == 204

    res = await client.request(
        "DELETE",
        f"/api/environments/{env_id}/lint/mute",
        headers=owner_headers,
        params={"name": "LEGACY_URL", "path": "/", "code": "plain_http"},
    )
    assert res.status_code == 204, res.text

    res = await client.get(f"/api/environments/{env_id}/lint", headers=owner_headers)
    assert [n["code"] for n in res.json()] == ["plain_http"]

async def test_muted_list_shows_text(client: httpx.AsyncClient, owner_headers, env_id):
    """Принятое замечание видно списком - с текстом, а не одним кодом."""
    await _put(client, owner_headers, env_id, "LEGACY_URL", "http://legacy.example.ru/api")
    await client.post(
        f"/api/environments/{env_id}/lint/mute",
        headers=owner_headers,
        json={"name": "LEGACY_URL", "path": "/", "code": "plain_http"},
    )

    res = await client.get(f"/api/environments/{env_id}/lint/mutes", headers=owner_headers)
    assert res.status_code == 200, res.text
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["name"] == "LEGACY_URL"
    assert rows[0]["text"] == "адрес без шифрования: http вместо https"
    assert rows[0]["muted_by"] == "owner"


async def test_copy_from_neighbour(client: httpx.AsyncClient, owner_headers, env_id):
    """Ключ переносится из соседнего окружения новой версией, источник не трогаем."""
    project_id = (
        await client.get("/api/projects", headers=owner_headers)
    ).json()[0]["id"]
    res = await client.post(
        f"/api/projects/{project_id}/environments",
        headers=owner_headers,
        json={"name": "stage"},
    )
    stage_id = res.json()["id"]

    await _put(client, owner_headers, stage_id, "NEW_FLAG", "value-from-stage")

    res = await client.post(
        f"/api/environments/{env_id}/copy-from",
        headers=owner_headers,
        json={"source": "stage", "name": "NEW_FLAG", "path": "/"},
    )
    assert res.status_code == 200, res.text

    here = await client.get(
        f"/api/environments/{env_id}/secret",
        headers=owner_headers,
        params={"name": "NEW_FLAG", "path": "/"},
    )
    assert here.json()["value"] == "value-from-stage"

    # Соседнее окружение осталось как было: перенос - это копия, а не переезд.
    there = await client.get(
        f"/api/environments/{stage_id}/secret",
        headers=owner_headers,
        params={"name": "NEW_FLAG", "path": "/"},
    )
    assert there.json()["value"] == "value-from-stage"


async def test_copy_from_unknown_environment(client: httpx.AsyncClient, owner_headers, env_id):
    res = await client.post(
        f"/api/environments/{env_id}/copy-from",
        headers=owner_headers,
        json={"source": "nowhere", "name": "ANY", "path": "/"},
    )
    assert res.status_code == 404

async def test_sweep_reports_once(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Обход сообщает о новом замечании один раз, о старом - молчит."""
    from app import lint_watch

    sent: list[str] = []

    async def fake_notify(session_factory, text: str) -> bool:
        sent.append(text)
        return True

    monkeypatch.setattr(lint_watch.alerts, "notify_later", fake_notify)

    await _put(client, owner_headers, env_id, "BACKUP_TOKEN", "changeme")

    # Берем то самое приложение, в котором сейф уже распечатан: у отдельного
    # экземпляра свой запертый сейф, и обход молчал бы по делу.
    app = client._transport.app  # type: ignore[attr-defined]
    first = await lint_watch.sweep(app.state.session_factory, app.state.sealbox)
    second = await lint_watch.sweep(app.state.session_factory, app.state.sealbox)

    assert first == 1, sent
    assert second == 0
    assert len(sent) == 1
    assert "BACKUP_TOKEN" in sent[0]
    # Значение в сообщение не попадает: там только место и текст замечания.
    assert "changeme" not in sent[0]

async def test_expiry_reminder_speaks_once(
    client: httpx.AsyncClient, owner_headers, env_id, monkeypatch
):
    """О подходящем сроке панель напоминает один раз и без значения.

    Проверка не читает значений, поэтому работает и у запертой панели: срок
    лежит у самого ключа.
    """
    from app import lint_watch
    from app.config import get_settings
    from app.db import create_engine_and_factory

    sent: list[str] = []

    async def fake_notify(session_factory, text: str) -> bool:
        sent.append(text)
        return True

    monkeypatch.setattr(lint_watch.alerts, "notify_later", fake_notify)

    await _put(client, owner_headers, env_id, "CERT_KEY", "секретное значение")
    soon = (datetime.now(timezone.utc) + timedelta(days=3)).date().isoformat()
    res = await client.post(
        f"/api/environments/{env_id}/secret/meta",
        headers=owner_headers,
        json={"name": "CERT_KEY", "path": "/", "note": "", "expires_at": soon},
    )
    assert res.status_code == 200, res.text

    engine, factory = create_engine_and_factory(get_settings().db_url)
    try:
        first = await lint_watch.sweep_expiry(factory)
        second = await lint_watch.sweep_expiry(factory)
    finally:
        await engine.dispose()

    assert first == 1, sent
    assert second == 0
    assert len(sent) == 1
    assert "CERT_KEY" in sent[0]
    assert "секретное значение" not in sent[0]
