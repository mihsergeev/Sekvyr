"""Проекты, значения которых сервер не видит.

Криптография здесь браузерная, поэтому тесты повторяют её ровно настолько,
насколько нужно серверу: он обязан хранить чужой шифротекст, отдавать обертки
тем, кому положено, и честно отказываться от всего, что требует открытого
текста. Проверяем именно это, а не стойкость шифра.
"""

import base64
import os

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import e2e
from tests.conftest import login

PROJECT_KEY = b"\x11" * 32


def seal(value: str) -> str:
    """То, что делает браузер: AES-GCM ключом проекта, в base64 с меткой."""
    nonce = os.urandom(12)
    blob = nonce + AESGCM(PROJECT_KEY).encrypt(nonce, value.encode(), b"")
    return e2e.PREFIX + base64.b64encode(blob).decode()


def open_sealed(value: str) -> str:
    raw = base64.b64decode(value[len(e2e.PREFIX) :])
    return AESGCM(PROJECT_KEY).decrypt(raw[:12], raw[12:], b"").decode()


def wrap_body() -> dict:
    """Обертка ключа проекта под паролем - тоже работа браузера."""
    return {
        "salt": base64.b64encode(b"s" * 16).decode(),
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "wrapped_key": base64.b64encode(b"w" * 48).decode(),
        "verifier_nonce": base64.b64encode(b"v" * 12).decode(),
        "verifier": base64.b64encode(b"m" * 32).decode(),
    }


async def _project(client, headers, slug="secret-app") -> dict:
    res = await client.post("/api/projects", headers=headers, json={"slug": slug})
    assert res.status_code == 201, res.text
    return res.json()


async def _env(client, headers, project_id: int, name="prod") -> dict:
    res = await client.post(
        f"/api/projects/{project_id}/environments", headers=headers, json={"name": name}
    )
    assert res.status_code == 201, res.text
    return res.json()


async def test_enable_and_read_wrap(client: httpx.AsyncClient, owner_headers, unsealed):
    project = await _project(client, owner_headers)
    res = await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    assert res.status_code == 200, res.text

    got = (await client.get(f"/api/projects/{project['id']}/e2e", headers=owner_headers)).json()
    assert got["enabled"] is True
    assert got["salt"] == wrap_body()["salt"]
    assert got["iterations"] == e2e.PBKDF2_ITERATIONS
    # Обертка возвращается как есть: раскрыть её панель не может ни при каких
    # правах, и это ровно то, ради чего режим существует.
    assert got["wrapped_key"] == wrap_body()["wrapped_key"]


async def test_cannot_enable_on_project_with_keys(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Иначе в одном проекте оказались бы значения двух разных видов."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.put(
        f"/api/environments/{env['id']}/secrets",
        headers=owner_headers,
        json={"name": "A", "value": "открытое", "path": "/"},
    )
    res = await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    assert res.status_code == 400
    assert "пустого" in res.json()["detail"]


async def test_plaintext_is_refused(client: httpx.AsyncClient, owner_headers, unsealed):
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    res = await client.put(
        f"/api/environments/{env['id']}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "открытым текстом", "path": "/"},
    )
    assert res.status_code == 400
    assert "запечатанные" in res.json()["detail"]


async def test_sealed_value_survives_the_round_trip(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Сервер хранит чужой шифротекст и отдает его в точности."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    sealed = seal("прод-пароль")
    res = await client.put(
        f"/api/environments/{env['id']}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": sealed, "path": "/"},
    )
    assert res.status_code == 200, res.text

    got = await client.get(
        f"/api/environments/{env['id']}/secret",
        headers=owner_headers,
        params={"name": "DB_PASSWORD", "path": "/"},
    )
    assert got.json()["value"] == sealed
    assert open_sealed(got.json()["value"]) == "прод-пароль"


async def test_server_never_sees_the_value(client: httpx.AsyncClient, owner_headers, unsealed):
    """Ни в ответах, ни в журнале открытого текста нет."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    await client.put(
        f"/api/environments/{env['id']}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": seal("совсем-секретно"), "path": "/"},
    )
    entries = await client.get("/api/audit", headers=owner_headers)
    assert "совсем-секретно" not in entries.text
    listing = await client.get(f"/api/environments/{env['id']}/secrets", headers=owner_headers)
    assert "совсем-секретно" not in listing.text


async def test_export_is_refused(client: httpx.AsyncClient, owner_headers, unsealed):
    """Файл из непрозрачных блобов хуже отсутствия файла."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    res = await client.get(f"/api/environments/{env['id']}/export", headers=owner_headers)
    assert res.status_code == 400
    assert "браузере" in res.json()["detail"]


async def test_copy_from_neighbour_keeps_the_seal(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Ключ проекта у всех окружений один: копия переезжает запечатанной и
    раскрывается тем же ключом. Раньше панель отказывала, хотя кнопку
    показывала."""
    project = await _project(client, owner_headers)
    prod = await _env(client, owner_headers, project["id"], "prod")
    stage = await _env(client, owner_headers, project["id"], "stage")
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    sealed = seal("общий-токен")
    await client.put(
        f"/api/environments/{prod['id']}/secrets",
        headers=owner_headers,
        json={"name": "TOKEN", "value": sealed, "path": "/"},
    )
    res = await client.post(
        f"/api/environments/{stage['id']}/copy-from",
        headers=owner_headers,
        json={"source": "prod", "name": "TOKEN", "path": "/"},
    )
    assert res.status_code == 200, res.text
    got = await client.get(
        f"/api/environments/{stage['id']}/secret",
        headers=owner_headers,
        params={"name": "TOKEN", "path": "/"},
    )
    assert got.json()["value"] == sealed
    assert open_sealed(got.json()["value"]) == "общий-токен"


async def test_import_is_refused_before_parsing(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Открытый файл в такой проект не заливается, и ответ говорит именно об
    этом, а не о плохом имени в одной из строк."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    res = await client.post(
        f"/api/environments/{env['id']}/import",
        headers=owner_headers,
        json={"text": "BAD NAME=x\nDB_PASSWORD=открытым текстом\n"},
    )
    assert res.status_code == 400
    assert "браузере" in res.json()["detail"]
    listing = await client.get(f"/api/environments/{env['id']}/secrets", headers=owner_headers)
    assert "DB_PASSWORD" not in listing.text


async def test_emergency_archive_says_it_cannot_help(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Пустое место в архиве должно быть объяснено, а не выглядеть потерей."""
    import io
    import json

    from app import sealedfile
    from tests.conftest import OWNER_PASSWORD

    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    await client.put(
        f"/api/environments/{env['id']}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": seal("важное"), "path": "/"},
    )
    res = await client.post(
        "/api/ops/emergency",
        headers=owner_headers,
        json={"password": "архивный-пароль-1", "login_password": OWNER_PASSWORD},
    )
    assert res.status_code == 200
    plain = io.BytesIO()
    sealedfile.unseal(io.BytesIO(res.content), plain, password="архивный-пароль-1")
    data = json.loads(plain.getvalue().decode())
    found = [p for p in data["projects"] if p["slug"] == "secret-app"][0]
    assert found["environments"][0]["values"] == []
    assert "браузере" in found["environments"][0]["note"]


async def test_machine_needs_the_project_key(client: httpx.AsyncClient, owner_headers, unsealed):
    """Без обертки агент получил бы блобы и молча положил их в файл."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    await client.put(
        f"/api/environments/{env['id']}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": seal("значение"), "path": "/"},
    )
    machine = (
        await client.post("/api/machines", headers=owner_headers, json={"name": "нода-1"})
    ).json()
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "machine",
            "subject_id": machine["id"],
            "environment_id": env["id"],
            "path_prefix": "/",
            "actions": ["read"],
            "effect": "allow",
        },
    )
    token = (
        await client.post(
            "/api/v1/machine/token",
            json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
        )
    ).json()["access_token"]
    head = {"Authorization": f"Bearer {token}"}

    res = await client.get(
        "/api/v1/machine/secrets",
        headers=head,
        params={"project": "secret-app", "env": "prod"},
    )
    assert res.status_code == 409
    assert "ключ проекта" in res.json()["detail"].lower()

    # Агент присылает свой публичный ключ отчетом.
    public = base64.b64encode(b"k" * 32).decode()
    assert (
        await client.post("/api/v1/machine/report", headers=head, json={"public_key": public})
    ).status_code == 200

    wrapped = {
        "machine_id": machine["id"],
        "ephemeral_public": base64.b64encode(b"e" * 32).decode(),
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "wrapped_key": base64.b64encode(b"w" * 48).decode(),
    }
    assert (
        await client.post(
            f"/api/projects/{project['id']}/e2e/machines",
            headers=owner_headers,
            json=wrapped,
        )
    ).status_code == 200

    res = await client.get(
        "/api/v1/machine/secrets",
        headers=head,
        params={"project": "secret-app", "env": "prod"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["e2e"] is True
    assert body["project_key"]["wrapped_key"] == wrapped["wrapped_key"]
    assert body["project_key"]["ephemeral_public"] == wrapped["ephemeral_public"]
    assert body["values"][0]["value"].startswith(e2e.PREFIX)


async def test_new_agent_key_drops_old_wraps(client: httpx.AsyncClient, owner_headers, unsealed):
    """Сменился ключ ноды - прежние обертки больше не раскроются, и висеть
    рабочими они не должны."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    machine = (
        await client.post("/api/machines", headers=owner_headers, json={"name": "нода-2"})
    ).json()
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "machine",
            "subject_id": machine["id"],
            "environment_id": env["id"],
            "path_prefix": "/",
            "actions": ["read"],
            "effect": "allow",
        },
    )
    token = (
        await client.post(
            "/api/v1/machine/token",
            json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
        )
    ).json()["access_token"]
    head = {"Authorization": f"Bearer {token}"}
    await client.post(
        "/api/v1/machine/report",
        headers=head,
        json={"public_key": base64.b64encode(b"k" * 32).decode()},
    )
    await client.post(
        f"/api/projects/{project['id']}/e2e/machines",
        headers=owner_headers,
        json={
            "machine_id": machine["id"],
            "ephemeral_public": base64.b64encode(b"e" * 32).decode(),
            "nonce": base64.b64encode(b"n" * 12).decode(),
            "wrapped_key": base64.b64encode(b"w" * 48).decode(),
        },
    )
    rows = (
        await client.get(f"/api/projects/{project['id']}/e2e/machines", headers=owner_headers)
    ).json()
    assert rows[0]["has_wrap"] is True

    await client.post(
        "/api/v1/machine/report",
        headers=head,
        json={"public_key": base64.b64encode(b"z" * 32).decode()},
    )
    rows = (
        await client.get(f"/api/projects/{project['id']}/e2e/machines", headers=owner_headers)
    ).json()
    assert rows[0]["has_wrap"] is False
    # Смена ключа названа в журнале: перед "Выдать заново" ее должно быть видно.
    log = (await client.get("/api/audit", headers=owner_headers, params={"q": "ключ ноды"})).json()
    assert any("ключ ноды сменился" in e["detail"] for e in log["entries"])


async def test_wrap_needs_machine_key(client: httpx.AsyncClient, owner_headers, unsealed):
    project = await _project(client, owner_headers)
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    machine = (
        await client.post("/api/machines", headers=owner_headers, json={"name": "нода-3"})
    ).json()
    res = await client.post(
        f"/api/projects/{project['id']}/e2e/machines",
        headers=owner_headers,
        json={
            "machine_id": machine["id"],
            "ephemeral_public": base64.b64encode(b"e" * 32).decode(),
            "nonce": base64.b64encode(b"n" * 12).decode(),
            "wrapped_key": base64.b64encode(b"w" * 48).decode(),
        },
    )
    assert res.status_code == 400
    assert "ключа" in res.json()["detail"]


async def test_wrap_is_hidden_from_strangers(client: httpx.AsyncClient, owner_headers, unsealed):
    """Обертка без пароля бесполезна, но и показывать её кому попало незачем."""
    project = await _project(client, owner_headers)
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "stranger", "password": "stranger-pass-26", "role": "developer"},
    )
    headers = await login(client, "stranger", "stranger-pass-26")
    res = await client.get(f"/api/projects/{project['id']}/e2e", headers=headers)
    assert res.status_code == 403


async def test_format_checks():
    e2e.check_value(seal("x"))
    for bad in ("открытый текст", e2e.PREFIX, e2e.PREFIX + "не base64!!"):
        try:
            e2e.check_value(bad)
        except e2e.FormatError:
            continue
        raise AssertionError(f"должно было отвергнуться: {bad}")


async def test_member_with_environment_or_folder_rights_gets_the_wrap(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Права людям выдают на окружение или папку, а не на проект целиком.
    Раньше обертку получали только владелец и те, кому выдан весь проект:
    разработчик с правом на prod не мог отпереть проект в браузере."""
    project = await _project(client, owner_headers)
    env = await _env(client, owner_headers, project["id"])
    await client.post(
        f"/api/projects/{project['id']}/e2e", headers=owner_headers, json=wrap_body()
    )
    for name, prefix in (("dev-env", "/"), ("dev-folder", "/db")):
        user = await client.post(
            "/api/users",
            headers=owner_headers,
            json={"username": name, "password": "member-pass-2026", "role": "developer"},
        )
        await client.post(
            "/api/policies",
            headers=owner_headers,
            json={
                "subject_type": "user",
                "subject_id": user.json()["id"],
                "environment_id": env["id"],
                "path_prefix": prefix,
                "actions": ["list", "read", "write"],
                "effect": "allow",
            },
        )
        headers = await login(client, name, "member-pass-2026")
        res = await client.get(f"/api/projects/{project['id']}/e2e", headers=headers)
        assert res.status_code == 200, (name, res.text)
        assert res.json()["wrapped_key"] == wrap_body()["wrapped_key"]
