"""Перенос секретов из Infisical и Vault KV.

Миграция - это не "залить и надеяться". Она устроена в два шага: сначала панель
показывает, что она видит на той стороне и что случится с каждым ключом, и
только потом переносит. Причина простая: чужой набор ключей поверх рабочего
окружения - самый быстрый способ незаметно испортить прод.

Что важно про оба источника:

  * **Реквизиты не сохраняются.** Токен Vault и пара Infisical живут внутри
    одного запроса и нигде не оседают. Панель не становится вторым местом, где
    лежит доступ к вашему старому хранилищу.
  * **Значения не попадают в журнал.** В журнал идет "перенесено N ключей", а
    не то, что в них было.
  * **Панель ходит по адресу, который назвали.** Self-hosted Infisical и Vault
    почти всегда стоят внутри периметра, поэтому проверку "только публичные
    адреса" здесь применить нельзя - и это записано в модели угроз. Закрыты
    только петля, link-local с метаданными облака и прочие служебные адреса
    (urlguard.check_source_url). Право на такой запрос есть только у того, кто
    и так распоряжается секретами окружения, а тело чужого ответа в ошибку не
    попадает: только то, что сам источник сказал об ошибке в своих полях.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx

TIMEOUT = 20


class SourceError(Exception):
    """Источник не ответил или ответил не тем: адрес, реквизиты, права."""


@dataclass
class Item:
    """Один ключ на той стороне."""

    path: str
    name: str
    value: str


@dataclass
class Fetched:
    items: list[Item] = field(default_factory=list)
    # Что стоит сказать человеку прежде, чем он нажмет "перенести".
    note: str = ""


def _client(verify_tls: bool = True) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT, verify=verify_tls, follow_redirects=False)


def _detail(response: httpx.Response) -> str:
    """Что источник сказал об ошибке, и только в своих полях: errors у Vault,
    message у Infisical. Тело целиком в ответ не идет: адрес задает человек,
    и пересказ чужой страницы превращал бы перенос в способ читать внутренние
    сервисы."""
    try:
        data = response.json()
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    errors = data.get("errors")
    if isinstance(errors, list):
        text = "; ".join(e for e in errors if isinstance(e, str))
    else:
        text = data.get("message") if isinstance(data.get("message"), str) else ""
    return text.strip()[:200]


def _fail(exc: Exception, what: str) -> SourceError:
    if isinstance(exc, httpx.HTTPStatusError):
        body = _detail(exc.response)
        return SourceError(f"{what}: HTTP {exc.response.status_code}" + (f" — {body}" if body else ""))
    return SourceError(f"{what}: {type(exc).__name__}")


# --- Infisical -------------------------------------------------------------


async def infisical_login(url: str, client_id: str, client_secret: str) -> str:
    """Машинная личность Infisical (Universal Auth) в обмен на токен."""
    base = url.rstrip("/")
    try:
        async with _client() as http:
            response = await http.post(
                f"{base}/api/v1/auth/universal-auth/login",
                json={"clientId": client_id, "clientSecret": client_secret},
            )
            response.raise_for_status()
            token = response.json().get("accessToken", "")
    except Exception as exc:  # noqa: BLE001
        raise _fail(exc, "вход в Infisical не удался") from exc
    if not token:
        raise SourceError("Infisical не вернул токен")
    return token


async def infisical_fetch(
    url: str,
    token: str,
    *,
    workspace_id: str,
    environment: str,
    secret_path: str = "/",
    recursive: bool = True,
) -> Fetched:
    """Секреты одного окружения Infisical.

    Читаем "сырые" значения (`/secrets/raw`): панель кладет их в свое
    хранилище зашифрованными сама, и получать шифротекст чужого формата ей
    незачем.
    """
    base = url.rstrip("/")
    params = {
        "workspaceId": workspace_id,
        "environment": environment,
        "secretPath": secret_path or "/",
        "include_imports": "true",
        "recursive": "true" if recursive else "false",
    }
    try:
        async with _client() as http:
            response = await http.get(
                f"{base}/api/v3/secrets/raw",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:  # noqa: BLE001
        raise _fail(exc, "Infisical не отдал секреты") from exc

    items: list[Item] = []
    for row in data.get("secrets", []):
        name = row.get("secretKey") or ""
        if not name:
            continue
        # Путь у Infisical свой ("/" или "/folder"), и он ложится на папки
        # панели один в один - это и есть вся "миграция структуры".
        folder = row.get("secretPath") or secret_path or "/"
        items.append(Item(path=folder, name=name, value=row.get("secretValue", "")))
    note = ""
    if data.get("imports"):
        note = (
            "у окружения есть импорты из других мест Infisical — они перенесены "
            "как обычные ключи, ссылками они больше не будут"
        )
    return Fetched(items=items, note=note)


async def infisical_projects(url: str, token: str) -> list[dict]:
    """Проекты, которые видит эта личность: чтобы не искать идентификатор руками."""
    base = url.rstrip("/")
    try:
        async with _client() as http:
            response = await http.get(
                f"{base}/api/v1/workspace", headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:  # noqa: BLE001
        raise _fail(exc, "Infisical не отдал список проектов") from exc
    out: list[dict] = []
    for row in data.get("workspaces", []):
        out.append(
            {
                "id": row.get("id") or row.get("_id") or "",
                "name": row.get("name", ""),
                "environments": [
                    e.get("slug", "") for e in row.get("environments", []) if e.get("slug")
                ],
            }
        )
    return out


# --- Vault KV v2 -----------------------------------------------------------


async def vault_fetch(url: str, token: str, *, mount: str, path: str = "") -> Fetched:
    """Все ключи поддерева KV v2.

    Обходим дерево сами: у Vault нет запроса "отдай все разом", а мигрируют
    обычно целый раздел, а не один секрет.

    Как ложится структура. В Vault один "секрет" - это набор пар, обычно как раз
    переменные одного приложения. Ключами становятся его поля, папкой - путь
    секрета от точки начала: секрет в самой точке ложится в целевую папку,
    точка/db - в папку /db. Так набор остается вместе, имена не склеиваются, и
    два секрета с одинаковыми полями не схлопываются в один ключ.
    """
    base = url.rstrip("/")
    mount = mount.strip("/")
    root = path.strip("/")
    headers = {"X-Vault-Token": token}
    items: list[Item] = []
    seen = 0

    def add(secret: str, payload: dict) -> None:
        rel = secret[len(root):].strip("/") if root else secret
        folder = "/" + rel if rel else "/"
        for name, value in payload.items():
            if value is None:
                text = ""
            elif isinstance(value, str):
                text = value
            else:
                # Числа, флаги и вложенные объекты - JSON, а не repr Питона:
                # True должно приехать как true, а словарь - как объект.
                text = json.dumps(value, ensure_ascii=False)
            items.append(Item(path=folder, name=name, value=text))

    async with _client() as http:

        async def read(secret: str) -> dict | None:
            """Поля секрета или None, если секрета нет: путь бывает только
            папкой, а удаленный секрет еще числится в списке, но данных не
            отдает. Ни то, ни другое не повод ронять весь перенос."""
            try:
                got = await http.get(f"{base}/v1/{mount}/data/{secret}", headers=headers)
                if got.status_code == 404:
                    return None
                got.raise_for_status()
                return got.json().get("data", {}).get("data") or {}
            except Exception as exc:  # noqa: BLE001
                raise _fail(exc, f"Vault не отдал секрет {secret}") from exc

        async def walk(current: str) -> None:
            nonlocal seen
            seen += 1
            if seen > 500:
                # Защита от бесконечного обхода: чужое дерево может быть каким
                # угодно, а панель не должна уходить в него навсегда.
                raise SourceError("в поддереве больше 500 узлов — сузьте путь")
            listing = f"{base}/v1/{mount}/metadata/{current}".rstrip("/")
            try:
                response = await http.request("LIST", listing, headers=headers)
                if response.status_code == 404:
                    return
                response.raise_for_status()
                keys = response.json().get("data", {}).get("keys", [])
            except SourceError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise _fail(exc, "Vault не отдал список") from exc

            for key in keys:
                child = f"{current.rstrip('/')}/{key}".lstrip("/") if current else key
                if key.endswith("/"):
                    await walk(child.rstrip("/"))
                    continue
                payload = await read(child)
                if payload is not None:
                    add(child, payload)

        # Точка начала сама бывает секретом - чаще всего так и есть: один секрет
        # на приложение. Список его "детей" при этом пуст или вовсе 404.
        if root:
            payload = await read(root)
            if payload is not None:
                add(root, payload)
        await walk(root)

    return Fetched(items=items, note="")
