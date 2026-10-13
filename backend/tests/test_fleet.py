"""Присмотр за парком: молчащие серверы и недельная сводка."""

from datetime import datetime, timedelta, timezone

import httpx

from app import fleet_watch, settings_store
from app.config import get_settings
from app.db import create_engine_and_factory
from app.models import MachineIdentity


async def _machine(client: httpx.AsyncClient, owner_headers, name: str) -> dict:
    res = await client.post(
        "/api/machines",
        headers=owner_headers,
        json={"name": name, "description": "", "allow_ips": "", "expires_at": ""},
    )
    assert res.status_code == 201, res.text
    return res.json()


async def _grant(client: httpx.AsyncClient, owner_headers, machine_id: int, env_id: int) -> None:
    res = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "machine",
            "subject_id": machine_id,
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": ["read"],
            "effect": "allow",
        },
    )
    assert res.status_code == 201, res.text


async def test_silent_server_reported_once(
    client: httpx.AsyncClient, owner_headers, env_id, monkeypatch
):
    """О замолчавшем сервере панель говорит один раз.

    Сервер, который сутки не забирает секреты, - это либо мертвый агент, либо
    мертвый сервер, и правка, отправленная туда, никуда не доехала. Но повторять
    это каждый час - верный способ научить людей не читать такие сообщения.
    """
    sent: list[str] = []

    async def fake_notify(session_factory, text: str) -> bool:
        sent.append(text)
        return True

    monkeypatch.setattr(fleet_watch.alerts, "notify_later", fake_notify)

    machine = await _machine(client, owner_headers, "web-1")
    await _grant(client, owner_headers, machine["id"], env_id)

    engine, factory = create_engine_and_factory(get_settings().db_url)
    try:
        # Ни разу не приходившая машина - это "еще не подключили", а не "пропала".
        assert await fleet_watch.sweep_silent(factory) == 0

        async with factory() as session:
            row = await session.get(MachineIdentity, machine["id"])
            row.last_seen_at = datetime.now(timezone.utc) - timedelta(hours=48)
            await session.commit()

        assert await fleet_watch.sweep_silent(factory) == 1, sent
        assert await fleet_watch.sweep_silent(factory) == 0
        assert len(sent) == 1
        assert "web-1" in sent[0]

        # Агент вернулся: панель забывает о нем и в следующий раз скажет заново.
        async with factory() as session:
            row = await session.get(MachineIdentity, machine["id"])
            row.last_seen_at = datetime.now(timezone.utc)
            await session.commit()
        assert await fleet_watch.sweep_silent(factory) == 0

        async with factory() as session:
            row = await session.get(MachineIdentity, machine["id"])
            row.last_seen_at = datetime.now(timezone.utc) - timedelta(hours=48)
            await session.commit()
        assert await fleet_watch.sweep_silent(factory) == 1
        assert len(sent) == 2
    finally:
        await engine.dispose()


async def test_digest_is_quiet_on_first_run(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed, monkeypatch
):
    """Первый запуск сводку не шлет: панель не должна здороваться письмом за
    неделю, которой еще не было."""
    sent: list[str] = []

    async def fake_notify(session_factory, text: str) -> bool:
        sent.append(text)
        return True

    monkeypatch.setattr(fleet_watch.alerts, "notify_later", fake_notify)

    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DIGEST_KEY", "value": "значение", "path": "/"},
    )

    engine, factory = create_engine_and_factory(get_settings().db_url)
    try:
        assert await fleet_watch.sweep_digest(factory) is False
        assert sent == []

        # Отматываем отметку на восемь дней назад: пора отправлять.
        async with factory() as session:
            await settings_store.put(
                session,
                fleet_watch.DIGEST_KEY,
                (datetime.now(timezone.utc) - timedelta(days=8)).isoformat(),
            )
            await session.commit()

        assert await fleet_watch.sweep_digest(factory) is True
        assert len(sent) == 1
        assert "owner" in sent[0]
        # Значений в сводке нет: она про число правок, а не про их содержимое.
        assert "значение" not in sent[0]
    finally:
        await engine.dispose()
