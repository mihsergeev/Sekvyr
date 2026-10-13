"""Владелец при старте панели и аварийный сброс его пароля."""

import httpx

from app import config
from app.bootstrap import ensure_owner
from tests.conftest import OWNER_PASSWORD, login


async def _restart(client: httpx.AsyncClient, monkeypatch, **env: str) -> None:
    """То, что делает старт панели, с другим .env."""
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    config.get_settings.cache_clear()
    app = client._transport.app
    await ensure_owner(app.state.session_factory, config.get_settings())


async def test_emergency_reset_happens_once(
    client: httpx.AsyncClient, owner_headers, monkeypatch
):
    """Забытый флаг не откатывает новый пароль на каждом рестарте и не снимает
    второй фактор снова и снова."""
    await _restart(
        client,
        monkeypatch,
        SEKVYR_ADMIN_PASSWORD_RESET="1",
        SEKVYR_ADMIN_PASSWORD="emergency-pass-2026",
    )
    headers = await login(client, "owner", "emergency-pass-2026")
    changed = await client.post(
        "/api/auth/password",
        headers=headers,
        json={"current_password": "emergency-pass-2026", "new_password": "after-reset-2026"},
    )
    assert changed.status_code == 204, changed.text

    await _restart(client, monkeypatch)
    await login(client, "owner", "after-reset-2026")
    log = await client.get(
        "/api/audit",
        headers=await login(client, "owner", "after-reset-2026"),
        params={"limit": 50},
    )
    resets = [e for e in log.json()["entries"] if e["action"] == "owner_password_reset"]
    assert len(resets) == 1


async def test_reset_password_must_be_long_enough(
    client: httpx.AsyncClient, owner_headers, monkeypatch
):
    import pytest

    with pytest.raises(RuntimeError):
        await _restart(
            client, monkeypatch, SEKVYR_ADMIN_PASSWORD_RESET="1", SEKVYR_ADMIN_PASSWORD="short"
        )
    await login(client, "owner", OWNER_PASSWORD)


async def test_other_owner_name_in_env_creates_nobody(
    client: httpx.AsyncClient, owner_headers, monkeypatch
):
    """Сменить имя владельца в .env - не способ завести еще одного владельца."""
    await _restart(
        client,
        monkeypatch,
        SEKVYR_ADMIN_USER="intruder",
        SEKVYR_ADMIN_PASSWORD="intruder-pass-2026",
    )
    res = await client.post(
        "/api/auth/login", json={"username": "intruder", "password": "intruder-pass-2026"}
    )
    assert res.status_code == 401
