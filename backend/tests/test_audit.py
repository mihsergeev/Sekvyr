"""Журнал: пишется ли и держится ли цепочка."""

import httpx
import pytest
from sqlalchemy import select

from app.models import AuditLog
from tests.conftest import OWNER_PASSWORD, login


async def test_login_is_recorded(client: httpx.AsyncClient, owner_headers):
    res = await client.get("/api/audit", headers=owner_headers)
    assert res.status_code == 200
    actions = [e["action"] for e in res.json()["entries"]]
    assert "login" in actions
    assert "owner_created" in actions


async def test_failed_login_is_recorded(client: httpx.AsyncClient, owner_headers):
    await client.post("/api/auth/login", json={"username": "owner", "password": "nope"})
    res = await client.get("/api/audit", headers=owner_headers)
    assert "login_failed" in [e["action"] for e in res.json()["entries"]]


async def test_secret_values_never_reach_the_log(client: httpx.AsyncClient, owner_headers):
    """Пароль не должен появиться в журнале ни в каком виде - ни как значение,
    ни как деталь события."""
    await client.post(
        "/api/auth/login", json={"username": "owner", "password": OWNER_PASSWORD}
    )
    res = await client.get("/api/audit", headers=owner_headers)
    dump = res.text
    assert OWNER_PASSWORD not in dump


async def test_timestamps_carry_a_timezone(client: httpx.AsyncClient, owner_headers):
    """Время уезжает наружу ТОЛЬКО с зоной: строку без нее браузер разберет как
    местное время, и журнал будет показывать события со сдвигом, выглядя при
    этом достоверно. SQLite отдает datetime без зоны, Postgres - с ней."""
    res = await client.get("/api/audit", headers=owner_headers)
    for entry in res.json()["entries"]:
        assert entry["ts"].endswith("+00:00"), entry["ts"]

    users = await client.get("/api/users", headers=owner_headers)
    for u in users.json():
        assert u["created_at"].endswith("+00:00"), u["created_at"]


async def test_chain_verifies(client: httpx.AsyncClient, owner_headers):
    await client.post("/api/auth/login", json={"username": "owner", "password": "nope"})
    res = await client.get("/api/audit/verify", headers=owner_headers)
    assert res.status_code == 200
    assert res.json() == {"ok": True, "broken_id": None, "breaks": 0}


async def test_tampering_is_detected(client: httpx.AsyncClient, owner_headers, monkeypatch):
    """Правка записи в обход панели ломает цепочку - это и есть весь смысл."""
    import app.main  # noqa: F401  (приложение уже создано фикстурой)

    from app.config import get_settings
    from app.db import create_engine_and_factory

    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        row = await session.scalar(select(AuditLog).order_by(AuditLog.id))
        row.actor = "кто-то другой"
        await session.commit()
        broken_id = row.id
    await engine.dispose()

    res = await client.get("/api/audit/verify", headers=owner_headers)
    assert res.json() == {"ok": False, "broken_id": broken_id, "breaks": 1}


async def test_two_edits_are_counted_separately(client: httpx.AsyncClient, owner_headers):
    """Одно расхождение - это правка строки, много - переписанный журнал.

    Число разрывов считается независимо: после первого пересчет продолжается от
    того, что записано, иначе одна подделка объявляла бы битым весь хвост и
    цифра ничего не значила бы.
    """
    from app.config import get_settings
    from app.db import create_engine_and_factory

    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        rows = list(await session.scalars(select(AuditLog).order_by(AuditLog.id)))
        assert len(rows) >= 2
        rows[0].actor = "подменили"
        rows[-1].detail = "и здесь тоже"
        await session.commit()
    await engine.dispose()

    body = (await client.get("/api/audit/verify", headers=owner_headers)).json()
    assert body["ok"] is False
    assert body["breaks"] == 2
    assert body["broken_id"] == rows[0].id


@pytest.mark.parametrize("role", ["developer", "viewer"])
async def test_low_roles_do_not_see_the_log(client: httpx.AsyncClient, owner_headers, role):
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "member", "password": "member-pass-2026", "role": role},
    )
    member = await login(client, "member", "member-pass-2026")
    assert (await client.get("/api/audit", headers=member)).status_code == 403


async def test_daily_check_reports_a_new_break_once(
    client: httpx.AsyncClient, owner_headers, monkeypatch
):
    """Цепочку раз в сутки проверяет сама панель. Об одном и том же
    расхождении она говорит один раз, о новом - снова."""
    from app import audit as audit_log
    from app import audit_watch
    from app.config import get_settings
    from app.db import create_engine_and_factory

    sent: list[str] = []

    async def fake_notify(session_factory, text: str) -> bool:
        sent.append(text)
        return True

    monkeypatch.setattr(audit_watch.alerts, "notify_later", fake_notify)
    # порции поменьше, чтобы проверка прошла через несколько из них
    monkeypatch.setattr(audit_log, "VERIFY_BATCH", 2)
    for _ in range(3):
        await client.post("/api/auth/login", json={"username": "owner", "password": "nope"})

    engine, factory = create_engine_and_factory(get_settings().db_url)
    try:
        assert await audit_watch.sweep(factory) is False
        async with factory() as session:
            rows = list(await session.scalars(select(AuditLog).order_by(AuditLog.id)))
            rows[2].actor = "кто-то другой"
            await session.commit()
            broken = rows[2].id
        assert await audit_watch.sweep(factory) is True
        assert f"№{broken} " in sent[0]
        assert await audit_watch.sweep(factory) is False
        assert len(sent) == 1
        async with factory() as session:
            row = await session.get(AuditLog, rows[4].id)
            row.detail = "подправлено"
            await session.commit()
        assert await audit_watch.sweep(factory) is True
        assert len(sent) == 2
    finally:
        await engine.dispose()
