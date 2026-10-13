"""Корневой ключ: заведение, отпирание, запирание, ротация."""

import httpx

from tests.conftest import login


async def test_starts_sealed_and_uninitialized(client: httpx.AsyncClient, owner_headers):
    res = await client.get("/api/vault/status", headers=owner_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["initialized"] is False
    assert body["sealed"] is True


async def test_health_shows_sealed(client: httpx.AsyncClient):
    """Снаружи должно быть видно, что панель жива, но значений не отдает."""
    body = (await client.get("/api/health")).json()
    assert body["sealed"] is True
    assert body["status"] == "sealed"


async def test_init_with_shares_and_unseal(client: httpx.AsyncClient, owner_headers):
    res = await client.post(
        "/api/vault/init",
        headers=owner_headers,
        json={"mode": "shares", "shares": 5, "threshold": 3},
    )
    assert res.status_code == 200, res.text
    shares = res.json()["shares"]
    assert len(shares) == 5
    assert res.json()["root_key"] == ""  # в режиме долей ключ целиком не показываем

    # после заведения панель открыта
    assert (await client.get("/api/vault/status", headers=owner_headers)).json()["sealed"] is False

    # запираем и собираем заново из трех долей
    assert (await client.post("/api/vault/seal", headers=owner_headers)).status_code == 200
    first = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": shares[0]})
    assert first.json()["sealed"] is True
    assert first.json()["pending_shares"] == 1
    second = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": shares[2]})
    assert second.json()["sealed"] is True
    third = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": shares[4]})
    assert third.json()["sealed"] is False


async def test_same_share_does_not_count_twice(client: httpx.AsyncClient, owner_headers):
    res = await client.post(
        "/api/vault/init",
        headers=owner_headers,
        json={"mode": "shares", "shares": 5, "threshold": 3},
    )
    shares = res.json()["shares"]
    await client.post("/api/vault/seal", headers=owner_headers)
    for _ in range(4):
        out = await client.post(
            "/api/vault/unseal", headers=owner_headers, json={"share": shares[0]}
        )
    assert out.json()["sealed"] is True
    assert out.json()["pending_shares"] == 1


async def test_foreign_share_is_refused(client: httpx.AsyncClient, owner_headers):
    """Доля от другого сейфа не должна ни отпирать, ни копиться."""
    from app import shamir

    await client.post(
        "/api/vault/init", headers=owner_headers, json={"mode": "shares", "shares": 3, "threshold": 2}
    )
    await client.post("/api/vault/seal", headers=owner_headers)
    alien = shamir.split(b"\x01" * 32, shares=3, threshold=2)
    res = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": alien[0]})
    assert res.status_code == 200  # доля принята как "одна из"...
    res = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": alien[1]})
    # ...но собранный из чужих долей ключ не сходится с маркером
    assert res.status_code == 400
    assert (await client.get("/api/vault/status", headers=owner_headers)).json()["sealed"] is True


async def test_cannot_init_twice(client: httpx.AsyncClient, owner_headers):
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    again = await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    assert again.status_code == 409


async def test_unseal_by_root_key(client: httpx.AsyncClient, owner_headers, unsealed):
    await client.post("/api/vault/seal", headers=owner_headers)
    bad = await client.post(
        "/api/vault/unseal", headers=owner_headers, json={"root_key": "AAAA"}
    )
    assert bad.status_code == 400
    good = await client.post(
        "/api/vault/unseal", headers=owner_headers, json={"root_key": unsealed}
    )
    assert good.json()["sealed"] is False


async def test_only_owner_initializes_and_seals(client: httpx.AsyncClient, owner_headers):
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "boss", "password": "member-pass-2026", "role": "maintainer"},
    )
    boss = await login(client, "boss", "member-pass-2026")
    assert (await client.post("/api/vault/init", headers=boss, json={"mode": "env"})).status_code == 403
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    assert (await client.post("/api/vault/seal", headers=boss)).status_code == 403
    # ...но подать долю ответственный может: доли раздают людям, а не ролям
    assert (await client.get("/api/vault/status", headers=boss)).status_code == 200


async def test_root_rotation_keeps_values_readable(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "prod-secret"},
    )
    res = await client.post("/api/vault/rotate-root", headers=owner_headers)
    assert res.status_code == 200, res.text
    assert res.json()["root_generation"] == 2
    assert res.json()["rewrapped_keys"] == 1

    value = await client.get(
        f"/api/environments/{env_id}/secret",
        headers=owner_headers,
        params={"name": "DB_PASSWORD"},
    )
    assert value.json()["value"] == "prod-secret"


async def test_new_environment_records_the_current_root_generation(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Окружение, заведенное после смены корневого ключа, записывалось с
    поколением 1, хотя обернуто ключом второго поколения."""
    from sqlalchemy import select

    from app.config import get_settings
    from app.db import create_engine_and_factory
    from app.models import EnvKey, Environment

    assert (await client.post("/api/vault/rotate-root", headers=owner_headers)).status_code == 200
    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        project_id = (await session.get(Environment, env_id)).project_id
    made = await client.post(
        f"/api/projects/{project_id}/environments", headers=owner_headers, json={"name": "after"}
    )
    assert made.status_code in (200, 201), made.text
    async with factory() as session:
        row = await session.scalar(select(EnvKey).where(EnvKey.environment_id == made.json()["id"]))
        assert row.root_generation == 2
    await engine.dispose()


async def test_old_root_key_stops_working_after_rotation(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Прежний ключ после ротации бесполезен - иначе "ротация" ничего не меняет
    для того, у кого утек старый ключ."""
    await client.post("/api/vault/rotate-root", headers=owner_headers)
    await client.post("/api/vault/seal", headers=owner_headers)
    res = await client.post(
        "/api/vault/unseal", headers=owner_headers, json={"root_key": unsealed}
    )
    assert res.status_code == 400


async def test_bad_share_counts_explain_themselves(client: httpx.AsyncClient, owner_headers):
    """Отказ должен приходить словами, а не как 422 со служебным списком: этот
    экран человек видит один раз в жизни и не должен угадывать, что ввел не так."""
    for body, expect in (
        ({"mode": "shares", "shares": 3, "threshold": 1}, "порог 1"),
        ({"mode": "shares", "shares": 1, "threshold": 1}, "хотя бы две"),
        ({"mode": "shares", "shares": 3, "threshold": 5}, "больше числа долей"),
    ):
        res = await client.post("/api/vault/init", headers=owner_headers, json=body)
        assert res.status_code == 400, (body, res.status_code, res.text)
        assert expect.lower() in res.json()["detail"].lower(), res.text
    # ни одна неудачная попытка не завела сейф наполовину
    assert (await client.get("/api/vault/status", headers=owner_headers)).json()["initialized"] is False


async def test_single_key_mode_remembers_the_intent(client: httpx.AsyncClient, owner_headers):
    """Панель запоминает, ждать ли ей ключ после перезапуска, и говорит, если
    намерение расходится с настройками. Иначе расхождение всплывает ровно в
    момент перезагрузки - когда его некому заметить."""
    res = await client.post(
        "/api/vault/init", headers=owner_headers, json={"mode": "env", "auto_unseal": True}
    )
    assert res.status_code == 200, res.text
    assert res.json()["root_key"]

    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["auto_unseal_intent"] is True
    # ключ в окружении не задан - панель должна это показывать
    assert status["root_key_configured"] is False


async def test_manual_key_mode_is_the_default(client: httpx.AsyncClient, owner_headers):
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["auto_unseal_intent"] is False


async def test_shares_mode_never_claims_auto_unseal(client: httpx.AsyncClient, owner_headers):
    """Доли и автоподъем несовместимы: собирать ключ из долей самому панель не
    умеет и не должна уметь."""
    await client.post(
        "/api/vault/init",
        headers=owner_headers,
        json={"mode": "shares", "shares": 3, "threshold": 2, "auto_unseal": True},
    )
    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["auto_unseal_intent"] is False


async def test_old_share_after_rotation_is_refused_cleanly(
    client: httpx.AsyncClient, owner_headers
):
    """Держатель подает долю от прежнего ключа: раньше это было 500 на каждой
    следующей доле, пока панель не перезапустят. Теперь отказ, набор
    сбрасывается, и новые доли открывают как обычно."""
    first = await client.post(
        "/api/vault/init", headers=owner_headers, json={"mode": "shares", "shares": 3, "threshold": 2}
    )
    old = first.json()["shares"]
    fresh = (await client.post("/api/vault/rotate-root", headers=owner_headers)).json()["shares"]
    await client.post("/api/vault/seal", headers=owner_headers)
    await client.post("/api/vault/unseal", headers=owner_headers, json={"share": old[0]})
    mixed = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": fresh[1]})
    assert mixed.status_code == 400, mixed.text
    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["sealed"] is True
    assert status.get("pending_shares", 0) == 0
    for share in fresh[:2]:
        out = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": share})
    assert out.json()["sealed"] is False


async def test_rotation_rewrites_the_remembered_key(
    client: httpx.AsyncClient, owner_headers, tmp_path, monkeypatch
):
    """Ключ, запомненный на сервере, меняется вместе с корнем: иначе после
    перезапуска панель не отопрется, а новый ключ мог никто не сохранить."""
    from app import config

    key_file = tmp_path / "secret" / "root.key"
    monkeypatch.setenv("SEKVYR_ROOT_KEY_FILE", str(key_file))
    config.get_settings.cache_clear()
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    remembered = await client.post("/api/vault/remember-key", headers=owner_headers)
    assert remembered.status_code == 200, remembered.text
    before = key_file.read_text()
    rotated = await client.post("/api/vault/rotate-root", headers=owner_headers)
    assert rotated.status_code == 200, rotated.text
    after = key_file.read_text()
    assert after != before
    assert after == rotated.json()["root_key"]
    assert not (key_file.parent / "root.key.new").exists()
