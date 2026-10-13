"""Вход, срок жизни токена и лимит попыток."""

import httpx

from app import ratelimit
from tests.conftest import OWNER_PASSWORD, login


async def test_login_and_me(client: httpx.AsyncClient, owner_headers: dict[str, str]):
    res = await client.get("/api/auth/me", headers=owner_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == "owner"
    assert body["role"] == "owner"
    assert body["level"] == 40


async def test_wrong_password_rejected(client: httpx.AsyncClient):
    res = await client.post(
        "/api/auth/login", json={"username": "owner", "password": "not-the-password"}
    )
    assert res.status_code == 401


async def test_unknown_user_looks_the_same(client: httpx.AsyncClient):
    """Ответ на несуществующую учетку не должен отличаться от неверного пароля -
    иначе перебором имен выясняют, кто в панели есть."""
    unknown = await client.post(
        "/api/auth/login", json={"username": "nobody", "password": "whatever-1234"}
    )
    wrong = await client.post(
        "/api/auth/login", json={"username": "owner", "password": "whatever-1234"}
    )
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


async def test_no_token_no_access(client: httpx.AsyncClient):
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_password_change_kills_old_tokens(
    client: httpx.AsyncClient, owner_headers: dict[str, str]
):
    res = await client.post(
        "/api/auth/password",
        headers=owner_headers,
        json={"current_password": OWNER_PASSWORD, "new_password": "new-owner-pass-2026"},
    )
    assert res.status_code == 204
    # старый токен больше не работает - важно, если пароль меняли из-за утечки
    assert (await client.get("/api/auth/me", headers=owner_headers)).status_code == 401
    fresh = await login(client, "owner", "new-owner-pass-2026")
    assert (await client.get("/api/auth/me", headers=fresh)).status_code == 200


async def test_short_password_refused(
    client: httpx.AsyncClient, owner_headers: dict[str, str]
):
    res = await client.post(
        "/api/auth/password",
        headers=owner_headers,
        json={"current_password": OWNER_PASSWORD, "new_password": "short"},
    )
    assert res.status_code == 422


async def test_brute_force_gets_locked(client: httpx.AsyncClient):
    for _ in range(ratelimit.MAX_FAILURES):
        await client.post(
            "/api/auth/login", json={"username": "owner", "password": "bad-guess"}
        )
    # порог достигнут: дальше отказ даже с ВЕРНЫМ паролем
    res = await client.post(
        "/api/auth/login", json={"username": "owner", "password": OWNER_PASSWORD}
    )
    assert res.status_code == 429


async def test_success_does_not_forgive_failures(
    client: httpx.AsyncClient, owner_headers: dict[str, str]
):
    """Подбирающий со своей учеткой не обнулит счетчик удачным входом."""
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "mallory", "password": "mallory-pass-2026", "role": "viewer"},
    )
    for _ in range(ratelimit.MAX_FAILURES - 1):
        await client.post("/api/auth/login", json={"username": "owner", "password": "guess"})
    own = await client.post(
        "/api/auth/login", json={"username": "mallory", "password": "mallory-pass-2026"}
    )
    assert own.status_code == 200
    await client.post("/api/auth/login", json={"username": "owner", "password": "guess"})
    res = await client.post(
        "/api/auth/login", json={"username": "owner", "password": OWNER_PASSWORD}
    )
    assert res.status_code == 429


def test_ipv6_network_is_one_subject():
    """Каждый новый адрес из своей /64 не начинает счет с нуля."""
    assert ratelimit.subject("2001:db8:1:2::1") == ratelimit.subject("2001:db8:1:2:ffff::9")
    assert ratelimit.subject("2001:db8:1:2::1") != ratelimit.subject("2001:db8:1:3::1")
    assert ratelimit.subject("203.0.113.7") == "203.0.113.7"
    assert ratelimit.subject("::ffff:203.0.113.7") == "203.0.113.7"


async def test_login_checks_account_addresses(
    client: httpx.AsyncClient, owner_headers: dict[str, str]
):
    """Верный пароль с чужого адреса - тот же отказ, что и неверный: иначе вход
    подсказывал бы, что пароль угадан."""
    user = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "office", "password": "office-pass-2026", "role": "developer"},
    )
    await client.patch(
        f"/api/users/{user.json()['id']}",
        headers=owner_headers,
        json={"allow_ips": "10.0.0.0/8"},
    )
    res = await client.post(
        "/api/auth/login", json={"username": "office", "password": "office-pass-2026"}
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Неверный логин или пароль"


async def test_long_password_is_explained(
    client: httpx.AsyncClient, owner_headers: dict[str, str]
):
    """bcrypt учитывает 72 байта, а сорок русских букв - это 80: отказ с
    объяснением, а не 500."""
    res = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "longpass", "password": "пароль" * 7, "role": "viewer"},
    )
    assert res.status_code == 400, res.text
    assert "72" in res.json()["detail"]


async def test_validation_error_does_not_echo_input(client: httpx.AsyncClient):
    """Мусор на входе не возвращается обратно целиком."""
    res = await client.post(
        "/api/auth/login", json={"username": "x" * 5000, "password": "y"}
    )
    assert res.status_code == 422
    assert "xxxxxxxxxx" not in res.text
    assert res.json()["detail"][0]["loc"][-1] == "username"
