"""Второй фактор."""

import asyncio
import time

import httpx
from sqlalchemy import Update
from sqlalchemy.ext.asyncio import AsyncSession

from app import ratelimit, totp
from app.api import auth
from tests.conftest import OWNER_PASSWORD


def _code(secret: str, shift: int = 0) -> str:
    return totp._code(secret, totp.counter_now() + shift)


async def _enable(client: httpx.AsyncClient, headers) -> tuple[str, dict[str, str]]:
    """Включает фактор и возвращает секрет и заголовки с новым токеном."""
    secret = (await client.post("/api/auth/2fa/start", headers=headers)).json()["secret"]
    res = await client.post(
        "/api/auth/2fa/enable",
        headers=headers,
        json={"code": _code(secret), "password": OWNER_PASSWORD},
    )
    assert res.status_code == 200, res.text
    return secret, {"Authorization": f"Bearer {res.json()['access_token']}"}


async def test_enable_and_login_with_code(client: httpx.AsyncClient, owner_headers):
    start = await client.post("/api/auth/2fa/start", headers=owner_headers)
    assert start.status_code == 200
    secret = start.json()["secret"]
    assert start.json()["otpauth_url"].startswith("otpauth://totp/Sekvyr:owner?")

    # пока код не подтвержден, фактор не включен - иначе легко остаться без входа
    me = await client.get("/api/auth/me", headers=owner_headers)
    assert me.json()["totp_enabled"] is False

    bad = await client.post(
        "/api/auth/2fa/enable",
        headers=owner_headers,
        json={"code": "000000", "password": OWNER_PASSWORD},
    )
    assert bad.status_code == 400

    ok = await client.post(
        "/api/auth/2fa/enable",
        headers=owner_headers,
        json={"code": _code(secret), "password": OWNER_PASSWORD},
    )
    assert ok.status_code == 200, ok.text
    fresh = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    # Сессия, открытая до включения, закрыта: иначе она проходила бы права
    # "только со вторым фактором". Новый токен из ответа работает.
    assert (await client.get("/api/auth/me", headers=owner_headers)).status_code == 401
    assert (await client.get("/api/auth/me", headers=fresh)).json()["totp_enabled"] is True

    # теперь вход без кода не проходит, но говорит, чего не хватает
    res = await client.post(
        "/api/auth/login", json={"username": "owner", "password": OWNER_PASSWORD}
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "2fa_required"

    res = await client.post(
        "/api/auth/login",
        json={"username": "owner", "password": OWNER_PASSWORD, "otp": "123456"},
    )
    assert res.json()["detail"] == "2fa_invalid"

    res = await client.post(
        "/api/auth/login",
        json={"username": "owner", "password": OWNER_PASSWORD, "otp": _code(secret, shift=1)},
    )
    assert res.status_code == 200, res.text


async def test_in_flight_start_cannot_replace_enabled_factor(client, owner_headers, monkeypatch):
    initial = await client.post("/api/auth/2fa/start", headers=owner_headers)
    assert initial.status_code == 200
    secret = initial.json()["secret"]
    started, release = asyncio.Event(), asyncio.Event()
    commit = AsyncSession.commit
    scalar = AsyncSession.scalar

    async def pause_stale_start():
        if asyncio.current_task() is stale_start and not started.is_set():
            started.set()
            await release.wait()

    async def pause_scalar(session, statement, *args, **kwargs):
        if isinstance(statement, Update):
            await pause_stale_start()
        return await scalar(session, statement, *args, **kwargs)

    async def pause_commit(session):
        await pause_stale_start()
        await commit(session)

    monkeypatch.setattr(AsyncSession, "scalar", pause_scalar)
    monkeypatch.setattr(AsyncSession, "commit", pause_commit)
    stale_start = asyncio.create_task(client.post("/api/auth/2fa/start", headers=owner_headers))
    try:
        await asyncio.wait_for(started.wait(), timeout=5)
        enabled = await client.post(
            "/api/auth/2fa/enable", headers=owner_headers,
            json={"code": _code(secret, shift=-1), "password": OWNER_PASSWORD},
        )
        assert enabled.status_code == 200
    finally:
        release.set()
        stale = await stale_start

    assert stale.status_code == 401
    logged_in = await client.post(
        "/api/auth/login",
        json={"username": "owner", "password": OWNER_PASSWORD, "otp": _code(secret)},
    )
    assert logged_in.status_code == 200


async def test_enable_needs_the_password(client: httpx.AsyncClient, owner_headers):
    """С украденной сессией без пароля фактор не привязать к своему телефону."""
    secret = (await client.post("/api/auth/2fa/start", headers=owner_headers)).json()["secret"]
    res = await client.post(
        "/api/auth/2fa/enable",
        headers=owner_headers,
        json={"code": _code(secret), "password": "не тот пароль"},
    )
    assert res.status_code == 400
    assert (await client.get("/api/auth/me", headers=owner_headers)).json()["totp_enabled"] is False


async def test_code_cannot_be_used_twice(client: httpx.AsyncClient, owner_headers):
    """Подсмотренный код иначе работал бы еще полминуты, и "одноразовый" он был
    бы только по названию."""
    secret = (await client.post("/api/auth/2fa/start", headers=owner_headers)).json()["secret"]
    code = _code(secret)
    await client.post(
        "/api/auth/2fa/enable",
        headers=owner_headers,
        json={"code": code, "password": OWNER_PASSWORD},
    )

    res = await client.post(
        "/api/auth/login", json={"username": "owner", "password": OWNER_PASSWORD, "otp": code}
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "2fa_invalid"


async def test_disable_requires_password_and_code(client: httpx.AsyncClient, owner_headers):
    secret, headers = await _enable(client, owner_headers)

    bad = await client.post(
        "/api/auth/2fa/disable",
        headers=headers,
        json={"password": "не тот пароль", "code": _code(secret, shift=1)},
    )
    assert bad.status_code == 400
    no_code = await client.post(
        "/api/auth/2fa/disable",
        headers=headers,
        json={"password": OWNER_PASSWORD, "code": "000000"},
    )
    assert no_code.status_code == 400
    assert (await client.get("/api/auth/me", headers=headers)).json()["totp_enabled"] is True

    ok = await client.post(
        "/api/auth/2fa/disable",
        headers=headers,
        json={"password": OWNER_PASSWORD, "code": _code(secret, shift=1)},
    )
    assert ok.status_code == 200, ok.text
    fresh = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    assert (await client.get("/api/auth/me", headers=fresh)).json()["totp_enabled"] is False
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 401


async def test_reauth_keeps_reservation_until_totp_is_checked(client, owner_headers, monkeypatch):
    _, headers = await _enable(client, owner_headers)
    app = client._transport.app
    async with app.state.session_factory() as session:
        for _ in range(ratelimit.MAX_FAILURES - 1):
            await ratelimit.record_failure(session, "reauth:1")

    started, release = asyncio.Event(), asyncio.Event()
    checked = 0

    async def wrong_code(*_args):
        nonlocal checked
        checked += 1
        if checked == 1:
            started.set()
            await release.wait()
        return False

    monkeypatch.setattr(auth, "consume_totp", wrong_code)
    body = {"password": OWNER_PASSWORD, "code": "000000"}
    first = asyncio.create_task(client.post("/api/auth/2fa/disable", headers=headers, json=body))
    try:
        await asyncio.wait_for(started.wait(), timeout=5)
        second = await client.post("/api/auth/2fa/disable", headers=headers, json=body)
    finally:
        release.set()
        result = await first

    assert result.status_code == 400
    assert second.status_code == 429
    assert checked == 1


async def test_foreign_digits_are_a_wrong_code(client: httpx.AsyncClient, owner_headers):
    """Арабские и надстрочные цифры - неверный код, а не 500 мимо лимитера."""
    await _enable(client, owner_headers)
    for code in ("١٢٣٤٥٦", "¹²³⁴⁵⁶"):
        res = await client.post(
            "/api/auth/login",
            json={"username": "owner", "password": OWNER_PASSWORD, "otp": code},
        )
        assert res.status_code == 401, res.text
        assert res.json()["detail"] == "2fa_invalid"


async def test_password_rechecks_are_limited(client: httpx.AsyncClient, owner_headers):
    """Повторная проверка пароля со своим счетчиком: с украденной сессией его
    не подобрать мимо лимитера входа."""
    for _ in range(ratelimit.MAX_FAILURES):
        res = await client.post(
            "/api/auth/password",
            headers=owner_headers,
            json={"current_password": "не тот пароль", "new_password": "new-password-2026"},
        )
        assert res.status_code == 400
    res = await client.post(
        "/api/auth/password",
        headers=owner_headers,
        json={"current_password": OWNER_PASSWORD, "new_password": "new-password-2026"},
    )
    assert res.status_code == 429
    log = await client.get("/api/audit", headers=owner_headers, params={"limit": 50})
    assert any(e["action"] == "reauth_failed" for e in log.json()["entries"])


def test_window_tolerance_is_narrow():
    """Допуск на часы - одно окно в каждую сторону: шире значит дольше живет
    подсмотренный код."""
    secret = totp.new_secret()
    now = time.time()
    assert totp.verify(secret, totp._code(secret, totp.counter_now(now) - 1), now=now)
    assert totp.verify(secret, totp._code(secret, totp.counter_now(now) + 1), now=now)
    assert totp.verify(secret, totp._code(secret, totp.counter_now(now) + 2), now=now) is None
    assert totp.verify(secret, "12345", now=now) is None
    assert totp.verify(secret, "не цифры", now=now) is None
    assert totp.verify(secret, "١٢٣٤٥٦", now=now) is None
