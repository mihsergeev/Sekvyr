"""Владелец снимает второй фактор с чужой учетки (1.0.1).

Падает на 1.0.0: такого маршрута не было, и потерянный телефон оставлял
человека без входа.
"""

from sqlalchemy import select

from app import totp
from app.models import AuditLog, User
from tests.conftest import login
from tests.pass11_helpers import PASS, _capture_alerts, _factory, _user


# --- 7. владелец снимает чужой второй фактор --------------------------------


async def test_owner_resets_someone_elses_second_factor(client, owner_headers, monkeypatch):
    oh = owner_headers
    did = await _user(client, oh, "dev", "developer")
    await _user(client, oh, "lead", "maintainer")
    dev = await login(client, "dev", PASS)
    secret = (await client.post("/api/auth/2fa/start", headers=dev)).json()["secret"]
    res = await client.post(
        "/api/auth/2fa/enable", headers=dev,
        json={"code": totp._code(secret, totp.counter_now()), "password": PASS},
    )
    assert res.status_code == 200, res.text
    dev = {"Authorization": f"Bearer {res.json()['access_token']}"}

    lead = await login(client, "lead", PASS)
    assert (await client.post(f"/api/users/{did}/2fa/reset", headers=lead)).status_code == 403

    sent = _capture_alerts(monkeypatch)
    res = await client.post(f"/api/users/{did}/2fa/reset", headers=oh)
    assert res.status_code == 200, res.text
    assert res.json()["totp_enabled"] is False
    assert sent == ["Sekvyr: owner снял второй фактор с учетной записи dev"]
    # Прежние сессии закрыты, а войти теперь можно одним паролем.
    assert (await client.get("/api/auth/me", headers=dev)).status_code == 401
    await login(client, "dev", PASS)
    assert (await client.post(f"/api/users/{did}/2fa/reset", headers=oh)).status_code == 409

    async with _factory(client)() as s:
        row = await s.scalar(select(AuditLog).where(AuditLog.action == "totp_disabled"))
    assert (row.actor, row.target, row.detail) == ("owner", "dev", "сброшен владельцем")


async def test_owner_cannot_reset_another_owners_second_factor(client, owner_headers):
    oh = owner_headers
    async with _factory(client)() as s:
        s.add(User(username="owner2", password_hash="x", role="owner"))
        await s.commit()
        other = await s.scalar(select(User.id).where(User.username == "owner2"))
    res = await client.post(f"/api/users/{other}/2fa/reset", headers=oh)
    assert res.status_code == 403, res.text
