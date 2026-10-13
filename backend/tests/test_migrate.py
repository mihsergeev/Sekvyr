"""Перенос из Infisical и Vault: что панель прочитает и что запишет.

Оба источника подставные - httpx с собственным транспортом. Проверяем разбор
ответов (у Infisical и Vault разные представления одного и того же), поведение
предпросмотра и то, что перенос по умолчанию ничего не переписывает.
"""

import base64

import httpx
import pytest

from app import importers
from tests.conftest import login

INFISICAL_URL = "https://infisical.example"
VAULT_URL = "https://vault.example"


def infisical_transport(secrets: list[dict], imports: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/universal-auth/login"):
            return httpx.Response(200, json={"accessToken": "infi-token"})
        if request.url.path.endswith("/api/v3/secrets/raw"):
            return httpx.Response(200, json={"secrets": secrets, "imports": imports or []})
        if request.url.path.endswith("/api/v1/workspace"):
            return httpx.Response(
                200,
                json={
                    "workspaces": [
                        {
                            "id": "ws-1",
                            "name": "Биллинг",
                            "environments": [{"slug": "prod"}, {"slug": "dev"}],
                        }
                    ]
                },
            )
        return httpx.Response(404, json={"message": "нет такого"})

    return httpx.MockTransport(handler)


def vault_transport(tree: dict[str, dict]):
    """tree: путь секрета -> его поля. Папки выводятся из путей."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "LIST":
            prefix = path.split("/metadata", 1)[1].strip("/")
            keys: set[str] = set()
            for full in tree:
                if prefix and not full.startswith(prefix + "/"):
                    continue
                rest = full[len(prefix) + 1 :] if prefix else full
                head, _, tail = rest.partition("/")
                keys.add(head + "/" if tail else head)
            if not keys:
                return httpx.Response(404, json={"errors": []})
            return httpx.Response(200, json={"data": {"keys": sorted(keys)}})
        if "/data/" in path:
            key = path.split("/data/", 1)[1]
            if tree.get(key) is None:
                return httpx.Response(404, json={"errors": []})
            return httpx.Response(200, json={"data": {"data": tree[key]}})
        return httpx.Response(404, json={"errors": []})

    return httpx.MockTransport(handler)


@pytest.fixture
def infisical(monkeypatch):
    rows = [
        {"secretKey": "DB_PASSWORD", "secretValue": "прод-пароль", "secretPath": "/"},
        {"secretKey": "TOKEN", "secretValue": "abc123", "secretPath": "/infra"},
    ]
    transport = infisical_transport(rows)
    original = importers._client

    def fake(verify_tls: bool = True):
        return httpx.AsyncClient(transport=transport, timeout=5)

    monkeypatch.setattr(importers, "_client", fake)
    yield rows
    monkeypatch.setattr(importers, "_client", original)


@pytest.fixture
def vault(monkeypatch):
    tree = {
        "billing/db": {"password": "прод-пароль"},
        "billing/api": {"key": "k1", "secret": "s1"},
        "billing/cache": {"password": "кэш-пароль"},
        # Один секрет на приложение, и под ним еще папка: так в Vault часто и
        # бывает. Секрет и папка с одним именем.
        "shop": {"DB_URL": "postgres://x", "PORT": 5432, "DEBUG": False, "LIMITS": {"rps": 10}},
        "shop/nested": {"TOKEN": "t1"},
        # Удаленный секрет: в списке есть, данных нет.
        "shop/gone": None,
        # Имя поля в Vault может быть любым, а пробел сломает файл на сервере.
        "shop/odd": {"BAD NAME": "x", "GOOD_ONE": "y"},
    }
    transport = vault_transport(tree)

    def fake(verify_tls: bool = True):
        return httpx.AsyncClient(transport=transport, timeout=5)

    monkeypatch.setattr(importers, "_client", fake)
    return tree


# --- разбор ответов источников --------------------------------------------


async def test_infisical_reads_values_and_folders(infisical):
    token = await importers.infisical_login(INFISICAL_URL, "id", "secret")
    assert token == "infi-token"
    fetched = await importers.infisical_fetch(
        INFISICAL_URL, token, workspace_id="ws-1", environment="prod"
    )
    assert {(i.path, i.name, i.value) for i in fetched.items} == {
        ("/", "DB_PASSWORD", "прод-пароль"),
        ("/infra", "TOKEN", "abc123"),
    }


async def test_infisical_projects(infisical):
    rows = await importers.infisical_projects(INFISICAL_URL, "infi-token")
    assert rows[0]["id"] == "ws-1"
    assert "prod" in rows[0]["environments"]


async def test_vault_walks_the_tree(vault):
    fetched = await importers.vault_fetch(VAULT_URL, "vault-token", mount="secret", path="billing")
    # Папка - путь секрета от точки начала, ключи - его поля без склейки. Два
    # секрета с одинаковым полем password не схлопываются: у каждого своя папка.
    assert {(i.path, i.name, i.value) for i in fetched.items} == {
        ("/db", "password", "прод-пароль"),
        ("/api", "key", "k1"),
        ("/api", "secret", "s1"),
        ("/cache", "password", "кэш-пароль"),
    }


async def test_vault_path_may_point_at_a_secret(vault):
    """Самый частый случай: один секрет на приложение, поля - его переменные.
    Раньше такой путь не переносил ничего: обходились только "дети" пути."""
    fetched = await importers.vault_fetch(VAULT_URL, "vault-token", mount="secret", path="billing/api")
    assert {(i.path, i.name, i.value) for i in fetched.items} == {("/", "key", "k1"), ("/", "secret", "s1")}


async def test_vault_secret_and_folder_with_one_name(vault):
    fetched = await importers.vault_fetch(VAULT_URL, "vault-token", mount="secret", path="shop")
    got = {(i.path, i.name): i.value for i in fetched.items}
    assert got[("/", "DB_URL")] == "postgres://x"
    assert got[("/nested", "TOKEN")] == "t1"
    # Не строки приезжают JSON, а не repr Питона.
    assert got[("/", "PORT")] == "5432"
    assert got[("/", "DEBUG")] == "false"
    assert got[("/", "LIMITS")] == '{"rps": 10}'
    # Удаленный секрет пропущен, а не уронил весь перенос.
    assert not any(path == "/gone" for path, _ in got)


async def test_vault_whole_mount(vault):
    fetched = await importers.vault_fetch(VAULT_URL, "vault-token", mount="secret", path="")
    paths = {i.path for i in fetched.items}
    assert {"/billing/db", "/billing/api", "/shop", "/shop/nested"} <= paths


async def test_vault_missing_path_is_empty(vault):
    fetched = await importers.vault_fetch(VAULT_URL, "vault-token", mount="secret", path="нет-такого")
    assert fetched.items == []


# --- предпросмотр и перенос -----------------------------------------------


async def _preview(client, headers, env_id, **extra):
    body = {
        "source": "infisical",
        "url": INFISICAL_URL,
        "client_id": "id",
        "client_secret": "secret",
        "workspace_id": "ws-1",
        "environment": "prod",
        "environment_id": env_id,
    }
    body.update(extra)
    return await client.post("/api/migrate/preview", headers=headers, json=body)


async def test_preview_says_what_will_happen(
    client: httpx.AsyncClient, owner_headers, env_id, infisical
):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "старое", "path": "/"},
    )
    res = await _preview(client, owner_headers, env_id)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total"] == 2
    assert body["create"] == 1 and body["update"] == 1
    # Значения в предпросмотр не попадают: только длина.
    assert "прод-пароль" not in res.text
    assert all("size" in row for row in body["rows"])


async def test_preview_marks_identical(client: httpx.AsyncClient, owner_headers, env_id, infisical):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "прод-пароль", "path": "/"},
    )
    body = (await _preview(client, owner_headers, env_id)).json()
    assert body["same"] == 1


async def test_apply_does_not_overwrite_by_default(
    client: httpx.AsyncClient, owner_headers, env_id, infisical
):
    """Чужой набор поверх рабочего окружения - самый быстрый способ испортить
    прод, поэтому по умолчанию существующее не трогается."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "своё", "path": "/"},
    )
    res = await client.post(
        "/api/migrate/apply",
        headers=owner_headers,
        json={
            "source": "infisical",
            "url": INFISICAL_URL,
            "client_id": "id",
            "client_secret": "secret",
            "workspace_id": "ws-1",
            "environment": "prod",
            "environment_id": env_id,
        },
    )
    assert res.status_code == 200, res.text
    assert res.json()["created"] == 1
    assert res.json()["skipped"] == ["DB_PASSWORD"]

    kept = await client.get(
        f"/api/environments/{env_id}/secret",
        headers=owner_headers,
        params={"name": "DB_PASSWORD", "path": "/"},
    )
    assert kept.json()["value"] == "своё"


async def test_apply_with_overwrite(client: httpx.AsyncClient, owner_headers, env_id, infisical):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "своё", "path": "/"},
    )
    res = await client.post(
        "/api/migrate/apply",
        headers=owner_headers,
        json={
            "source": "infisical",
            "url": INFISICAL_URL,
            "client_id": "id",
            "client_secret": "secret",
            "workspace_id": "ws-1",
            "environment": "prod",
            "environment_id": env_id,
            "overwrite": True,
        },
    )
    assert res.json()["updated"] == 1
    now = await client.get(
        f"/api/environments/{env_id}/secret",
        headers=owner_headers,
        params={"name": "DB_PASSWORD", "path": "/"},
    )
    assert now.json()["value"] == "прод-пароль"


async def test_apply_keeps_folders(client: httpx.AsyncClient, owner_headers, env_id, infisical):
    await client.post(
        "/api/migrate/apply",
        headers=owner_headers,
        json={
            "source": "infisical",
            "url": INFISICAL_URL,
            "client_id": "id",
            "client_secret": "secret",
            "workspace_id": "ws-1",
            "environment": "prod",
            "environment_id": env_id,
        },
    )
    listing = (
        await client.get(f"/api/environments/{env_id}/secrets", headers=owner_headers)
    ).json()
    places = {(s["path"], s["name"]) for s in listing}
    assert ("/infra", "TOKEN") in places


async def test_values_do_not_reach_the_log(
    client: httpx.AsyncClient, owner_headers, env_id, infisical
):
    await client.post(
        "/api/migrate/apply",
        headers=owner_headers,
        json={
            "source": "infisical",
            "url": INFISICAL_URL,
            "client_id": "id",
            "client_secret": "secret",
            "workspace_id": "ws-1",
            "environment": "prod",
            "environment_id": env_id,
        },
    )
    entries = (await client.get("/api/audit", headers=owner_headers)).json()["entries"]
    migrated = [e for e in entries if e["action"] == "secrets_migrated"]
    assert migrated, "перенос должен оставлять след"
    assert "прод-пароль" not in str(entries)


async def test_migration_needs_write_right(
    client: httpx.AsyncClient, owner_headers, env_id, infisical
):
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "keeper", "password": "keeper-pass-2026", "role": "maintainer"},
    )
    headers = await login(client, "keeper", "keeper-pass-2026")
    res = await _preview(client, headers, env_id)
    assert res.status_code == 403


async def test_bad_credentials_are_explained(client: httpx.AsyncClient, owner_headers, env_id):
    res = await _preview(client, owner_headers, env_id, client_id="", client_secret="")
    assert res.status_code == 400
    assert "личности" in res.json()["detail"]


async def test_identical_keys_are_not_reported_as_skipped(
    client: httpx.AsyncClient, owner_headers, env_id, infisical
):
    """"Пропущено 40" о совпадающих значениях тревожит там, где ничего не
    произошло: в пропущенные идут только те, где перезапись что-то изменила бы."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "прод-пароль", "path": "/"},
    )
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "TOKEN", "value": "другое", "path": "/infra"},
    )
    res = await client.post(
        "/api/migrate/apply",
        headers=owner_headers,
        json={
            "source": "infisical",
            "url": INFISICAL_URL,
            "client_id": "id",
            "client_secret": "secret",
            "workspace_id": "ws-1",
            "environment": "prod",
            "environment_id": env_id,
        },
    )
    body = res.json()
    assert body["created"] == 0 and body["updated"] == 0
    assert body["skipped"] == ["TOKEN"]


async def test_apply_skips_names_that_break_the_file(
    client: httpx.AsyncClient, owner_headers, env_id, vault
):
    """Один ключ с плохим именем не роняет весь перенос: он в пропущенных."""
    res = await client.post(
        "/api/migrate/apply",
        headers=owner_headers,
        json={
            "source": "vault",
            "url": VAULT_URL,
            "token": "vault-token",
            "mount": "secret",
            "path": "shop/odd",
            "environment_id": env_id,
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["created"] == 1
    assert any("BAD NAME" in name for name in body["skipped"])


async def test_migration_into_e2e_project_is_refused(
    client: httpx.AsyncClient, owner_headers, env_id, monkeypatch
):
    """Отказ раньше похода в источник: открытые значения не должны даже
    доехать до панели, если положить их все равно некуда."""
    calls: list[str] = []

    def fake(verify_tls: bool = True):
        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(500)

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5)

    monkeypatch.setattr(importers, "_client", fake)
    projects = (await client.get("/api/projects", headers=owner_headers)).json()
    project_id = next(p["id"] for p in projects if p["slug"] == "billing")
    wrap = {
        "salt": base64.b64encode(b"s" * 16).decode(),
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "wrapped_key": base64.b64encode(b"w" * 48).decode(),
        "verifier_nonce": base64.b64encode(b"v" * 12).decode(),
        "verifier": base64.b64encode(b"m" * 32).decode(),
    }
    res = await client.post(f"/api/projects/{project_id}/e2e", headers=owner_headers, json=wrap)
    assert res.status_code == 200, res.text

    res = await _preview(client, owner_headers, env_id)
    assert res.status_code == 400
    assert "браузере" in res.json()["detail"]
    res = await client.post(
        "/api/migrate/apply",
        headers=owner_headers,
        json={
            "source": "vault",
            "url": VAULT_URL,
            "token": "vault-token",
            "mount": "secret",
            "path": "shop",
            "environment_id": env_id,
        },
    )
    assert res.status_code == 400
    assert "браузере" in res.json()["detail"]
    assert calls == []


async def test_preview_does_not_tell_equality_without_read_right(
    client: httpx.AsyncClient, owner_headers, env_id, infisical
):
    """С одним правом записи "совпадает" в предпросмотре было бы способом
    угадывать чужое значение: источник человек задает сам, и каждая догадка
    проверялась бы молча. Без права читать совпадение не сообщается."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "прод-пароль", "path": "/"},
    )
    user = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "writer", "password": "writer-pass-2026", "role": "maintainer"},
    )
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "user",
            "subject_id": user.json()["id"],
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": ["list", "write"],
            "effect": "allow",
        },
    )
    writer = await login(client, "writer", "writer-pass-2026")

    def action(body):
        return next(r["action"] for r in body["rows"] if r["name"] == "DB_PASSWORD")

    assert action((await _preview(client, owner_headers, env_id)).json()) == "совпадает"
    res = await _preview(client, writer, env_id)
    assert res.status_code == 200, res.text
    assert action(res.json()) == "обновить"
    assert res.json()["same"] == 0


async def test_source_inside_the_panel_is_refused(
    client: httpx.AsyncClient, owner_headers, env_id, monkeypatch
):
    """Петля изнутри контейнера - это сама панель, 169.254.169.254 - метаданные
    облака. Vault там быть не может, а ответ мог бы быть ценен, поэтому запрос
    не уходит вовсе. Частная сеть при этом разрешена: свой Vault почти всегда
    стоит в ней."""
    calls: list[str] = []

    def fake(verify_tls: bool = True):
        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(404, json={"errors": []})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5)

    monkeypatch.setattr(importers, "_client", fake)
    for url in (
        "http://127.0.0.1:8200",
        "http://localhost:8200",
        "http://169.254.169.254",
        "http://[::ffff:127.0.0.1]:8200",
        "http://[fe80::1]:8200",
        "http://100.100.100.200",
        "ftp://vault.example",
        "http://vault.example:99999",
    ):
        res = await _preview(client, owner_headers, env_id, source="vault", url=url, token="t")
        assert res.status_code == 400, f"{url}: {res.text}"
    assert calls == []

    inside = await _preview(
        client, owner_headers, env_id, source="vault", url="http://10.1.2.3:8200", token="t"
    )
    assert inside.status_code == 200, inside.text
    assert calls


async def test_source_page_is_not_retold(
    client: httpx.AsyncClient, owner_headers, env_id, monkeypatch
):
    """Тело чужого ответа в ошибку не идет: адрес задает человек, и пересказ
    страницы превращал бы перенос в способ читать внутренние сервисы. То, что
    сам Vault сказал в поле errors, - идет: без этого не понять, что не так."""

    def fake(verify_tls: bool = True):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "page.example":
                return httpx.Response(502, text="<html>internal-page-text</html>")
            return httpx.Response(403, json={"errors": ["permission denied"]})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5)

    monkeypatch.setattr(importers, "_client", fake)
    page = await _preview(
        client, owner_headers, env_id, source="vault", url="https://page.example", token="t"
    )
    assert page.status_code == 400
    assert "HTTP 502" in page.json()["detail"]
    assert "internal-page-text" not in page.text
    vault = await _preview(
        client, owner_headers, env_id, source="vault", url="https://vault.example", token="t"
    )
    assert "permission denied" in vault.json()["detail"]


async def test_infisical_projects_need_the_target_environment(
    client: httpx.AsyncClient, owner_headers, env_id, infisical
):
    """Список проектов Infisical - тот же поход в чужую сеть, что и перенос,
    и право на него то же: запись в окружение, куда переносят."""
    body = {"url": INFISICAL_URL, "client_id": "id", "client_secret": "secret"}
    missing = await client.post("/api/migrate/infisical/projects", headers=owner_headers, json=body)
    assert missing.status_code == 422
    ok = await client.post(
        "/api/migrate/infisical/projects",
        headers=owner_headers,
        json={**body, "environment_id": env_id},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()[0]["id"] == "ws-1"

    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "keeper", "password": "keeper-pass-2026", "role": "maintainer"},
    )
    keeper = await login(client, "keeper", "keeper-pass-2026")
    denied = await client.post(
        "/api/migrate/infisical/projects",
        headers=keeper,
        json={**body, "environment_id": env_id},
    )
    assert denied.status_code == 403
