"""Перенос: что нашел одиннадцатый проход.

Предпросмотр переноса в закрытую папку, импорты Infisical, ответы источника не
того формата и не того размера и ключи, которые перенос все равно пропустит.
"""

import httpx
import pytest

from app import importers
from tests.conftest import login

PASS = "member-pass-2026"
SOURCE = "http://10.0.0.5"


async def _user(client, oh, name, role="maintainer") -> int:
    res = await client.post(
        "/api/users", headers=oh, json={"username": name, "password": PASS, "role": role}
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _policy(client, oh, **body) -> None:
    body.setdefault("path_prefix", "/")
    body.setdefault("effect", "allow")
    res = await client.post("/api/policies", headers=oh, json=body)
    assert res.status_code == 201, res.text


async def _project_id(client, oh) -> int:
    return (await client.get("/api/projects", headers=oh)).json()[0]["id"]


async def _put(client, h, env, name, value, path="/"):
    res = await client.put(
        f"/api/environments/{env}/secrets",
        headers=h,
        json={"name": name, "value": value, "path": path},
    )
    assert res.status_code == 200, res.text


def _vault_items(monkeypatch, *items: importers.Item) -> dict:
    async def fake_fetch(url, token, *, mount, path=""):
        return importers.Fetched(items=list(items))

    monkeypatch.setattr(importers, "vault_fetch", fake_fetch)
    return {"source": "vault", "url": SOURCE + ":8200", "token": "t"}


def _mock_client(monkeypatch, handler) -> None:
    def make(verify_tls: bool = True):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)

    monkeypatch.setattr(importers, "_client", make)


INFISICAL = {
    "source": "infisical",
    "url": SOURCE,
    "client_id": "c",
    "client_secret": "s",
    "workspace_id": "w",
    "environment": "prod",
}


# --- предпросмотр не отвечает за папки, куда человеку нельзя ------------------


async def _lead_without(client, oh, env_id, actions: list[str]) -> dict:
    """Ответственный с правами на проект и запретом actions на /private."""
    pid = await _project_id(client, oh)
    uid = await _user(client, oh, "lead")
    await _policy(
        client, oh, subject_type="user", subject_id=uid, project_id=pid,
        actions=["list", "read", "write"],
    )
    await _policy(
        client, oh, subject_type="user", subject_id=uid, environment_id=env_id,
        path_prefix="/private", effect="deny", actions=actions,
    )
    return await login(client, "lead", PASS)


async def test_preview_into_denied_folder_is_refused(client, owner_headers, env_id, monkeypatch):
    """Раньше предпросмотр отвечал "обновить" про существующий ключ закрытой
    папки и "создать" про несуществующий, а перенос туда же получал 403."""
    await _put(client, owner_headers, env_id, "HIDDEN_KEY", "x", path="/private")
    lead = await _lead_without(client, owner_headers, env_id, ["list", "read", "write"])
    source = _vault_items(
        monkeypatch,
        importers.Item(path="/private", name="HIDDEN_KEY", value="guess"),
        importers.Item(path="/private", name="NO_SUCH_KEY", value="guess"),
    )
    res = await client.post(
        "/api/migrate/preview", headers=lead, json={**source, "environment_id": env_id}
    )
    assert res.status_code == 403, res.text
    assert "HIDDEN_KEY" not in res.text


async def test_preview_in_write_only_folder_does_not_tell_existing(
    client, owner_headers, env_id, monkeypatch
):
    """Писать в папку можно, видеть ее ключи нельзя: "создать" и "обновить"
    сказали бы, какой ключ там есть. Обе строки - одинаковое "записать"."""
    await _put(client, owner_headers, env_id, "HIDDEN_KEY", "x", path="/private")
    lead = await _lead_without(client, owner_headers, env_id, ["list", "read"])
    source = _vault_items(
        monkeypatch,
        importers.Item(path="/private", name="HIDDEN_KEY", value="guess"),
        importers.Item(path="/private", name="NO_SUCH_KEY", value="guess"),
    )
    res = await client.post(
        "/api/migrate/preview", headers=lead, json={**source, "environment_id": env_id}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert {r["name"]: r["action"] for r in body["rows"]} == {
        "HIDDEN_KEY": "записать",
        "NO_SUCH_KEY": "записать",
    }
    assert body["create"] == 0 and body["update"] == 0 and body["write"] == 2


# --- предпросмотр не обещает того, что перенос пропустит ----------------------


async def test_preview_marks_names_apply_will_skip(client, owner_headers, env_id, monkeypatch):
    source = _vault_items(
        monkeypatch,
        importers.Item(path="/", name="smtp/host", value="v"),
        importers.Item(path="/", name="BAD NAME", value="v"),
        importers.Item(path="/bad folder", name="GOOD", value="v"),
        importers.Item(path="/", name="FINE", value="v"),
    )
    body = {**source, "environment_id": env_id}
    preview = (await client.post("/api/migrate/preview", headers=owner_headers, json=body)).json()
    rows = {(r["path"], r["name"]): r for r in preview["rows"]}
    assert rows[("/", "FINE")]["action"] == "создать"
    for key, reason in (
        (("/", "smtp/host"), "недопустимое имя"),
        (("/", "BAD NAME"), "недопустимое имя"),
        (("/bad folder", "GOOD"), "недопустимая папка"),
    ):
        assert rows[key]["action"] == "пропустить" and rows[key]["reason"] == reason
    assert preview["create"] == 1 and preview["skip"] == 3

    applied = (await client.post("/api/migrate/apply", headers=owner_headers, json=body)).json()
    assert applied["created"] == preview["create"]
    assert len(applied["skipped"]) == preview["skip"]


# --- Infisical: импорты и скрытые значения -------------------------------------


def _infisical_handler(answer: dict, *, v4: bool, seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/universal-auth/login"):
            return httpx.Response(200, json={"accessToken": "t"})
        seen.append((path, dict(request.url.params)))
        if path == "/api/v4/secrets" and v4:
            return httpx.Response(200, json=answer)
        if path == "/api/v3/secrets/raw" and not v4:
            return httpx.Response(200, json=answer)
        return httpx.Response(404, json={"message": "Not Found"})

    return handler


IMPORTED = {
    "secrets": [
        {"secretKey": "OWN", "secretValue": "own", "secretPath": "/"},
        {"secretKey": "DUP", "secretValue": "own", "secretPath": "/"},
    ],
    # Формат Infisical: блоки импортов со своими secrets. Последний блок
    # важнее предыдущих, собственный ключ окружения важнее любого импорта.
    "imports": [
        {
            "secretPath": "/",
            "environment": "shared",
            "folderId": "f1",
            "secrets": [
                {"secretKey": "DUP", "secretValue": "first", "secretPath": "/"},
                {"secretKey": "A", "secretValue": "first", "secretPath": "/"},
            ],
        },
        {
            "secretPath": "/",
            "environment": "common",
            "folderId": "f2",
            "secrets": [
                {"secretKey": "A", "secretValue": "second", "secretPath": "/"},
                {"secretKey": "B", "secretValue": "second", "secretPath": "/"},
            ],
        },
    ],
}


@pytest.mark.parametrize("v4", [True, False], ids=["v4", "v3-raw"])
async def test_infisical_imports_are_moved(client, owner_headers, env_id, monkeypatch, v4):
    """Раньше панель писала, что импорты перенесены, а их ключей не было вовсе."""
    seen: list = []
    _mock_client(monkeypatch, _infisical_handler(IMPORTED, v4=v4, seen=seen))
    body = {**INFISICAL, "environment_id": env_id}
    preview = (await client.post("/api/migrate/preview", headers=owner_headers, json=body)).json()
    assert {r["name"] for r in preview["rows"]} == {"OWN", "DUP", "A", "B"}
    assert "ключей из импортов Infisical: 2" in preview["note"]

    applied = await client.post("/api/migrate/apply", headers=owner_headers, json=body)
    assert applied.status_code == 200, applied.text
    assert applied.json()["created"] == 4
    res = await client.get(f"/api/environments/{env_id}/values", headers=owner_headers)
    values = {r["name"]: r["value"] for r in res.json()}
    assert values["DUP"] == "own"
    assert values["A"] == "second"
    assert values["B"] == "second"

    # Импорты и раскрытые ссылки просим явно, в именах параметров своей версии.
    path, params = seen[-1]
    if v4:
        assert path == "/api/v4/secrets"
        assert params["projectId"] == "w" and params["includeImports"] == "true"
        assert params["viewSecretValue"] == "true"
    else:
        assert path == "/api/v3/secrets/raw"
        assert params["workspaceId"] == "w" and params["include_imports"] == "true"
    assert params["expandSecretReferences"] == "true"


async def test_infisical_hidden_value_is_not_moved(client, owner_headers, env_id, monkeypatch):
    """Без права на значение Infisical отдает заглушку: в прод она не едет."""
    answer = {
        "secrets": [
            {"secretKey": "OPEN", "secretValue": "1", "secretPath": "/"},
            {
                "secretKey": "CLOSED",
                "secretValue": "<hidden-by-infisical>",
                "secretValueHidden": True,
                "secretPath": "/",
            },
        ],
        "imports": [],
    }
    _mock_client(monkeypatch, _infisical_handler(answer, v4=True, seen=[]))
    body = {**INFISICAL, "environment_id": env_id}
    preview = (await client.post("/api/migrate/preview", headers=owner_headers, json=body)).json()
    closed = next(r for r in preview["rows"] if r["name"] == "CLOSED")
    assert closed["action"] == "пропустить" and "не отдал значение" in closed["reason"]

    applied = (await client.post("/api/migrate/apply", headers=owner_headers, json=body)).json()
    assert applied["created"] == 1
    res = await client.get(f"/api/environments/{env_id}/values", headers=owner_headers)
    assert "CLOSED" not in {r["name"] for r in res.json()}


# --- ответ не того формата и не того размера -----------------------------------


@pytest.mark.parametrize(
    "content",
    [
        b"[]",
        b'{"secrets": ["A=1"]}',
        b'{"secrets": [{"secretKey": "A", "secretValue": 5}]}',
        b'{"secrets": [], "imports": {"a": 1}}',
        b'{"secrets": [], "imports": [{"secrets": "x"}]}',
        b"<html>proxy</html>",
        b"\xff\xfe\x00garbage",
    ],
    ids=["list", "row-string", "value-number", "imports-dict", "import-rows", "html", "not-utf8"],
)
async def test_infisical_odd_answer_is_explained(client, owner_headers, env_id, monkeypatch, content):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/universal-auth/login"):
            return httpx.Response(200, json={"accessToken": "t"})
        return httpx.Response(200, content=content)

    _mock_client(monkeypatch, handler)
    res = await client.post(
        "/api/migrate/preview", headers=owner_headers, json={**INFISICAL, "environment_id": env_id}
    )
    assert res.status_code == 400, res.text
    assert "не в том формате" in res.json()["detail"]


async def test_infisical_null_value_is_empty(client, owner_headers, env_id, monkeypatch):
    answer = {"secrets": [{"secretKey": "A", "secretValue": None}]}
    _mock_client(monkeypatch, _infisical_handler(answer, v4=True, seen=[]))
    res = await client.post(
        "/api/migrate/preview", headers=owner_headers, json={**INFISICAL, "environment_id": env_id}
    )
    assert res.status_code == 200, res.text
    assert res.json()["rows"][0]["size"] == 0


@pytest.mark.parametrize(
    "answer",
    [
        {"data": {"data": ["x"]}},
        {"data": "x"},
        [],
    ],
    ids=["data-list", "data-string", "body-list"],
)
async def test_vault_odd_secret_is_explained(client, owner_headers, env_id, monkeypatch, answer):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "LIST":
            return httpx.Response(404)
        return httpx.Response(200, json=answer)

    _mock_client(monkeypatch, handler)
    res = await client.post(
        "/api/migrate/preview",
        headers=owner_headers,
        json={"source": "vault", "url": SOURCE + ":8200", "token": "t", "path": "app",
              "environment_id": env_id},
    )
    assert res.status_code == 400, res.text
    assert "не в том формате" in res.json()["detail"]


async def test_vault_odd_listing_is_explained(client, owner_headers, env_id, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "LIST":
            return httpx.Response(200, json={"data": {"keys": [1, 2]}})
        return httpx.Response(404)

    _mock_client(monkeypatch, handler)
    res = await client.post(
        "/api/migrate/preview",
        headers=owner_headers,
        json={"source": "vault", "url": SOURCE + ":8200", "token": "t", "environment_id": env_id},
    )
    assert res.status_code == 400, res.text
    assert "не в том формате" in res.json()["detail"]


@pytest.mark.parametrize("declared", [True, False], ids=["content-length", "chunked"])
async def test_oversized_answer_is_cut_while_reading(
    client, owner_headers, env_id, monkeypatch, declared
):
    """Предел проверяется по ходу чтения: поток без длины иначе читался бы
    в память целиком."""
    monkeypatch.setattr(importers, "MAX_BYTES", 4096)
    sent = {"bytes": 0}

    async def endless():
        for _ in range(1000):
            sent["bytes"] += 1024
            yield b" " * 1024

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/universal-auth/login"):
            return httpx.Response(200, json={"accessToken": "t"})
        if declared:
            return httpx.Response(200, content=b" " * 10_000)
        return httpx.Response(200, content=endless())

    _mock_client(monkeypatch, handler)
    res = await client.post(
        "/api/migrate/preview", headers=owner_headers, json={**INFISICAL, "environment_id": env_id}
    )
    assert res.status_code == 400, res.text
    assert "сузьте путь" in res.json()["detail"]
    if not declared:
        assert sent["bytes"] < 100 * 1024


async def test_too_many_keys_stop_the_read(client, owner_headers, env_id, monkeypatch):
    monkeypatch.setattr(importers, "MAX_ITEMS", 3)
    answer = {"secrets": [{"secretKey": f"K{i}", "secretValue": "v"} for i in range(10)]}
    _mock_client(monkeypatch, _infisical_handler(answer, v4=True, seen=[]))
    res = await client.post(
        "/api/migrate/preview", headers=owner_headers, json={**INFISICAL, "environment_id": env_id}
    )
    assert res.status_code == 400, res.text
    assert "больше 3 ключей" in res.json()["detail"]
