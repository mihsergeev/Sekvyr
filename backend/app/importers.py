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
  * **Ответ источника проверяется.** Он читается не больше MAX_BYTES и не
    больше MAX_ITEMS ключей, а ответ не того формата (прокси с заглушкой,
    другая версия, чужой сервис по этому адресу) - понятная ошибка, а не 500.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx

TIMEOUT = 20
# Предел одного ответа источника и числа ключей. Проверяются по ходу чтения:
# адрес задает человек, и сервер, отдающий бесконечный поток или миллион
# ключей, иначе съел бы память панели раньше, чем сработала бы проверка.
MAX_BYTES = 20 * 1024 * 1024
MAX_ITEMS = 5000


class SourceError(Exception):
    """Источник не ответил или ответил не тем: адрес, реквизиты, права."""


@dataclass
class Item:
    """Один ключ на той стороне."""

    path: str
    name: str
    value: str
    # Почему ключ не переносится, если не переносится: источник не отдал
    # значение. Предпросмотр показывает такой ключ пропускаемым, а перенос его
    # не пишет: вместо значения в прод уехала бы заглушка.
    skip: str = ""


@dataclass
class Fetched:
    items: list[Item] = field(default_factory=list)
    # Что стоит сказать человеку прежде, чем он нажмет "перенести".
    note: str = ""


def _client(verify_tls: bool = True) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT, verify=verify_tls, follow_redirects=False)


def _detail_of(data) -> str:
    """Что источник сказал об ошибке, и только в своих полях: errors у Vault,
    message у Infisical. Тело целиком в ответ не идет: адрес задает человек,
    и пересказ чужой страницы превращал бы перенос в способ читать внутренние
    сервисы."""
    if not isinstance(data, dict):
        return ""
    errors = data.get("errors")
    if isinstance(errors, list):
        text = "; ".join(e for e in errors if isinstance(e, str))
    else:
        text = data.get("message") if isinstance(data.get("message"), str) else ""
    return text.strip()[:200]


def _fail(exc: Exception, what: str) -> SourceError:
    return SourceError(f"{what}: {type(exc).__name__}")


def _odd(what: str) -> SourceError:
    """Источник ответил, но не тем, что описано в его API."""
    return SourceError(f"{what}: ответ не в том формате, что описан в API источника")


def _status(what: str, code: int, data) -> SourceError:
    detail = _detail_of(data)
    return SourceError(f"{what}: HTTP {code}" + (f" — {detail}" if detail else ""))


async def _get_json(http: httpx.AsyncClient, method: str, url: str, what: str, **kwargs):
    """(код ответа, разобранный JSON или None).

    Тело читается кусками и не дальше MAX_BYTES. Успешный ответ не JSON или
    не UTF-8 - понятная ошибка. 404 отдается вызывающему: где-то он значит
    "нет такого секрета", где-то - "старая версия API".
    """
    too_big = f"{what}: ответ больше {MAX_BYTES // 2**20} МБ, сузьте путь"
    try:
        async with http.stream(method, url, **kwargs) as response:
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > MAX_BYTES:
                raise SourceError(too_big)
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > MAX_BYTES:
                    raise SourceError(too_big)
            code = response.status_code
    except SourceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _fail(exc, what) from exc
    try:
        data = json.loads(bytes(body)) if body else None
    except ValueError:
        data = None
    if code == 404:
        return code, data
    if not 200 <= code < 300:
        raise _status(what, code, data)
    if data is None:
        raise _odd(what)
    return code, data


# --- Infisical -------------------------------------------------------------


async def infisical_login(url: str, client_id: str, client_secret: str) -> str:
    """Машинная личность Infisical (Universal Auth) в обмен на токен."""
    base = url.rstrip("/")
    what = "вход в Infisical не удался"
    async with _client() as http:
        code, data = await _get_json(
            http,
            "POST",
            f"{base}/api/v1/auth/universal-auth/login",
            what,
            json={"clientId": client_id, "clientSecret": client_secret},
        )
    if code == 404:
        raise _status(what, code, data)
    token = data.get("accessToken") if isinstance(data, dict) else None
    if not isinstance(token, str) or not token:
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

    Читаем открытые значения: панель кладет их в свое хранилище
    зашифрованными сама, и получать шифротекст чужого формата ей незачем.
    Ссылки на другие ключи (${KEY}) раскрываются: переносится то, что видит
    приложение, а сама панель таких ссылок не понимает.

    Нынешний API - /api/v4/secrets. Self-hosted Infisical до его появления
    отвечает на него 404, тогда берем /api/v3/secrets/raw: ответ у них один.
    """
    base = url.rstrip("/")
    root = secret_path or "/"
    what = "Infisical не отдал секреты"
    headers = {"Authorization": f"Bearer {token}"}
    flag = "true" if recursive else "false"
    async with _client() as http:
        code, data = await _get_json(
            http,
            "GET",
            f"{base}/api/v4/secrets",
            what,
            headers=headers,
            params={
                "projectId": workspace_id,
                "environment": environment,
                "secretPath": root,
                "includeImports": "true",
                "recursive": flag,
                "expandSecretReferences": "true",
                "viewSecretValue": "true",
            },
        )
        if code == 404:
            code, data = await _get_json(
                http,
                "GET",
                f"{base}/api/v3/secrets/raw",
                what,
                headers=headers,
                params={
                    "workspaceId": workspace_id,
                    "environment": environment,
                    "secretPath": root,
                    "include_imports": "true",
                    "recursive": flag,
                    "expandSecretReferences": "true",
                },
            )
            if code == 404:
                raise _status(what, code, data)

    if not isinstance(data, dict):
        raise _odd(what)
    own = data.get("secrets", [])
    imports = data.get("imports") or []
    if not isinstance(own, list) or not isinstance(imports, list):
        raise _odd(what)

    items: list[Item] = []
    taken: set[tuple[str, str]] = set()

    def add(row, folder: str) -> None:
        if not isinstance(row, dict):
            raise _odd(what)
        name = row.get("secretKey")
        if not isinstance(name, str) or not name or (folder, name) in taken:
            return
        value = row.get("secretValue")
        if value is None:
            value = ""
        elif not isinstance(value, str):
            raise _odd(what)
        if len(items) >= MAX_ITEMS:
            raise SourceError(f"на той стороне больше {MAX_ITEMS} ключей, сузьте путь")
        taken.add((folder, name))
        if row.get("secretValueHidden") is True:
            # Без права на значение Infisical отдает заглушку. Перенести ее
            # значит положить в прод не тот пароль, поэтому ключ пропускается.
            note = "Infisical не отдал значение: у машинной личности нет права его читать"
            items.append(Item(path=folder, name=name, value="", skip=note))
            return
        items.append(Item(path=folder, name=name, value=value))

    for row in own:
        # Путь у Infisical свой ("/" или "/folder"), и он ложится на папки
        # панели один в один - это и есть вся "миграция структуры".
        folder = row.get("secretPath") if isinstance(row, dict) else None
        add(row, folder if isinstance(folder, str) and folder else root)

    # Импорты Infisical отдает отдельно, а сливает их клиент: ключ самого
    # окружения важнее импортированного, из импортов побеждает последний (так
    # делает их CLI). Импорт живет в папке, которую читали, туда же ложатся и
    # его ключи.
    brought = 0
    for block in reversed(imports):
        rows = block.get("secrets", []) if isinstance(block, dict) else None
        if not isinstance(rows, list):
            raise _odd(what)
        before = len(items)
        for row in rows:
            add(row, root)
        brought += len(items) - before

    note = ""
    if brought:
        note = (
            f"ключей из импортов Infisical: {brought}. Они переносятся как обычные ключи "
            "и ссылками больше не будут, а ключ самого окружения важнее "
            "импортированного с тем же именем"
        )
    return Fetched(items=items, note=note)


async def infisical_projects(url: str, token: str) -> list[dict]:
    """Проекты, которые видит эта личность: чтобы не искать идентификатор руками."""
    base = url.rstrip("/")
    what = "Infisical не отдал список проектов"
    async with _client() as http:
        code, data = await _get_json(
            http,
            "GET",
            f"{base}/api/v1/workspace",
            what,
            headers={"Authorization": f"Bearer {token}"},
        )
    if code == 404:
        raise _status(what, code, data)
    rows = data.get("workspaces", []) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise _odd(what)
    out: list[dict] = []
    for row in rows:
        envs = row.get("environments", []) if isinstance(row, dict) else None
        if not isinstance(envs, list):
            raise _odd(what)
        ident = row.get("id") or row.get("_id") or ""
        name = row.get("name", "")
        out.append(
            {
                "id": ident if isinstance(ident, str) else "",
                "name": name if isinstance(name, str) else "",
                "environments": [
                    e["slug"]
                    for e in envs
                    if isinstance(e, dict) and isinstance(e.get("slug"), str) and e["slug"]
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
            if len(items) >= MAX_ITEMS:
                raise SourceError(f"на той стороне больше {MAX_ITEMS} ключей, сузьте путь")
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
            what = f"Vault не отдал секрет {secret}"
            code, got = await _get_json(
                http, "GET", f"{base}/v1/{mount}/data/{secret}", what, headers=headers
            )
            if code == 404:
                return None
            if not isinstance(got, dict):
                raise _odd(what)
            outer = got.get("data")
            fields = outer.get("data") if isinstance(outer, dict) else outer
            if fields is None:
                return {}
            if not isinstance(fields, dict):
                raise _odd(what)
            return fields

        async def walk(current: str) -> None:
            nonlocal seen
            seen += 1
            if seen > 500:
                # Защита от бесконечного обхода: чужое дерево может быть каким
                # угодно, а панель не должна уходить в него навсегда.
                raise SourceError("в поддереве больше 500 узлов — сузьте путь")
            listing = f"{base}/v1/{mount}/metadata/{current}".rstrip("/")
            what = "Vault не отдал список"
            code, got = await _get_json(http, "LIST", listing, what, headers=headers)
            if code == 404:
                return
            outer = got.get("data") if isinstance(got, dict) else None
            keys = outer.get("keys", []) if isinstance(outer, dict) else None
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                raise _odd(what)

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
