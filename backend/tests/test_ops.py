"""Обслуживание: запечатанные файлы, аварийный архив, оповещения, копия журнала.

Главная проверка здесь - не "работает ли кнопка", а "откроется ли это в день,
когда панели уже нет". Поэтому файлы, которые пишет панель, читаются в тестах
именно аварийной утилитой `ops/breakglass.py`, а не своими же функциями: два
куска кода, которые обязаны понимать друг друга, должны встречаться в тестах, а
не в аварии.
"""

import argparse
import base64
import importlib.util
import io
import json
import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app import sealedfile
from app.config import get_settings
from app.db import create_engine_and_factory
from app.models import EnvKey, Environment, Project, Secret, SecretVersion
from tests.conftest import OWNER_PASSWORD


def _breakglass():
    """Загружаем ops/breakglass.py как модуль: он живет вне пакета намеренно."""
    path = Path(__file__).resolve().parents[2] / "ops" / "breakglass.py"
    spec = importlib.util.spec_from_file_location("breakglass", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


breakglass = _breakglass()


# --- формат запечатанного файла -------------------------------------------


def _seal(data: bytes, password: str = "пароль-для-теста") -> bytes:
    out = io.BytesIO()
    sealedfile.seal(io.BytesIO(data), out, password=password, note="тест")
    return out.getvalue()


def test_seal_roundtrip():
    data = b"nothing to see here" * 1000
    out = io.BytesIO()
    sealedfile.unseal(io.BytesIO(_seal(data)), out, password="пароль-для-теста")
    assert out.getvalue() == data


def test_seal_hides_plaintext():
    assert b"DB_PASSWORD" not in _seal(b"DB_PASSWORD=hunter2")


def test_wrong_password_is_rejected():
    with pytest.raises(sealedfile.SealedError):
        sealedfile.unseal(io.BytesIO(_seal(b"x")), io.BytesIO(), password="другой")


def test_multichunk_file_survives():
    """Файл длиннее куска: важна склейка и то, что счетчик nonce не сбивается."""
    data = bytes(range(256)) * 20000  # ~5 МБ, пять кусков
    out = io.BytesIO()
    sealedfile.unseal(io.BytesIO(_seal(data)), out, password="пароль-для-теста")
    assert out.getvalue() == data


def test_truncated_file_is_rejected():
    """Обрезанный бэкап не должен открываться "наполовину": половина дампа,
    выданная за целый, обнаруживается через месяц."""
    blob = _seal(bytes(range(256)) * 20000)
    with pytest.raises(sealedfile.SealedError):
        sealedfile.unseal(io.BytesIO(blob[: len(blob) // 2]), io.BytesIO(), password="пароль-для-теста")


def test_header_tampering_is_rejected():
    """Заголовок входит в связанные данные: подменить пометку, оставив
    содержимое, не выйдет."""
    blob = _seal("важное содержимое".encode())
    head, newline, rest = blob.partition(b"\n")
    spoiled = head.replace('"note": "тест"'.encode(), '"note": "иное"'.encode())
    assert spoiled != head
    with pytest.raises(sealedfile.SealedError):
        sealedfile.unseal(
            io.BytesIO(spoiled + newline + rest), io.BytesIO(), password="пароль-для-теста"
        )


def test_breakglass_opens_what_panel_sealed():
    """Утилита аварийного доступа и панель говорят на одном языке."""
    data = b"-- pg_dump --\nCOPY public.x (id) FROM stdin;\n1\n\\.\n"
    out = io.BytesIO()
    head = breakglass.unseal(io.BytesIO(_seal(data)), out, "пароль-для-теста")
    assert out.getvalue() == data
    assert head["kind"] == "backup" or head["note"] == "тест"


def test_format_constants_match():
    """Формат описан в двух местах - и они не должны разъезжаться."""
    assert breakglass.MAGIC == sealedfile.MAGIC
    assert breakglass.SCRYPT_N == sealedfile.SCRYPT_N
    assert breakglass.NONCE_PREFIX == sealedfile.NONCE_PREFIX


# --- аварийный архив -------------------------------------------------------


async def _put(client, headers, env_id, name, value, path="/"):
    res = await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )
    assert res.status_code == 200, res.text


async def test_emergency_archive_opens_without_panel(
    client: httpx.AsyncClient, owner_headers, env_id, tmp_path
):
    await _put(client, owner_headers, env_id, "DB_PASSWORD", "prod-пароль")
    await _put(client, owner_headers, env_id, "TOKEN", "многострочное\nзначение", path="/infra")

    res = await client.post(
        "/api/ops/emergency",
        headers=owner_headers,
        json={
            "password": "архивный-пароль-1",
            "login_password": OWNER_PASSWORD,
            "note": "проверка",
        },
    )
    assert res.status_code == 200, res.text
    assert b"prod-\xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c" not in res.content

    archive = tmp_path / "emergency.sealed"
    archive.write_bytes(res.content)

    # Открываем ровно так, как это будет в аварии: чужой утилитой и паролем.
    plain = io.BytesIO()
    with archive.open("rb") as src:
        breakglass.unseal(src, plain, "архивный-пароль-1")
    data = json.loads(plain.getvalue().decode())
    values = data["projects"][0]["environments"][0]["values"]
    assert {v["name"]: v["value"] for v in values} == {
        "DB_PASSWORD": "prod-пароль",
        "TOKEN": "многострочное\nзначение",
    }


async def test_emergency_needs_own_password(client: httpx.AsyncClient, owner_headers, env_id):
    res = await client.post(
        "/api/ops/emergency",
        headers=owner_headers,
        json={"password": "архивный-пароль-1", "login_password": "не тот"},
    )
    assert res.status_code == 403


async def test_emergency_password_must_be_long(client: httpx.AsyncClient, owner_headers, env_id):
    """Короткий пароль ломает всю затею: архив подбирают офлайн, без панели."""
    res = await client.post(
        "/api/ops/emergency",
        headers=owner_headers,
        json={"password": "коротко", "login_password": OWNER_PASSWORD},
    )
    assert res.status_code == 422


async def test_emergency_is_written_to_log(client: httpx.AsyncClient, owner_headers, env_id):
    await client.post(
        "/api/ops/emergency",
        headers=owner_headers,
        json={"password": "архивный-пароль-1", "login_password": OWNER_PASSWORD},
    )
    entries = (await client.get("/api/audit", headers=owner_headers)).json()["entries"]
    assert any(e["action"] == "emergency_archive" for e in entries)


async def test_emergency_needs_owner(client: httpx.AsyncClient, owner_headers, env_id):
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "reader", "password": "reader-pass-2026", "role": "viewer"},
    )
    from tests.conftest import login

    headers = await login(client, "reader", "reader-pass-2026")
    res = await client.post(
        "/api/ops/emergency",
        headers=headers,
        json={"password": "архивный-пароль-1", "login_password": "reader-pass-2026"},
    )
    assert res.status_code == 403


# --- бэкап базы читается аварийной утилитой --------------------------------


def _copy_block(table: str, rows: list[dict]) -> str:
    """Кусок plain-дампа pg_dump для таблицы: так его и разбирает breakglass."""
    if not rows:
        return ""
    columns = list(rows[0])
    out = [f"COPY public.{table} ({', '.join(columns)}) FROM stdin;"]
    for row in rows:
        fields = []
        for name in columns:
            value = row[name]
            if value is None:
                fields.append("\\N")
            else:
                text = str(value)
                fields.append(
                    text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
                )
        out.append("\t".join(fields))
    out.append("\\.")
    return "\n".join(out) + "\n"


async def test_backup_dump_can_be_decrypted_offline(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed, tmp_path
):
    """Сценарий "есть дамп и корневой ключ, панели нет"."""
    await _put(client, owner_headers, env_id, "DB_PASSWORD", "prod-пароль")
    await _put(client, owner_headers, env_id, "TOKEN", "две\nстроки", path="/infra")

    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        projects = [
            {"id": p.id, "slug": p.slug, "group_slug": p.group_slug, "title": p.title}
            for p in await session.scalars(select(Project))
        ]
        environments = [
            {"id": e.id, "project_id": e.project_id, "parent_id": e.parent_id, "name": e.name}
            for e in await session.scalars(select(Environment))
        ]
        env_keys = [
            {
                "id": k.id,
                "environment_id": k.environment_id,
                "generation": k.generation,
                "nonce": k.nonce,
                "wrapped_key": k.wrapped_key,
            }
            for k in await session.scalars(select(EnvKey))
        ]
        secrets = [
            {
                "id": s.id,
                "environment_id": s.environment_id,
                "path": s.path,
                "name": s.name,
                "current_version": s.current_version,
                "deleted": "t" if s.deleted else "f",
            }
            for s in await session.scalars(select(Secret))
        ]
        versions = [
            {
                "id": v.id,
                "secret_id": v.secret_id,
                "version": v.version,
                "name_at": v.name_at,
                "path_at": v.path_at,
                "deleted": "t" if v.deleted else "f",
                "inherits": "t" if v.inherits else "f",
                "nonce": v.nonce,
                "ciphertext": v.ciphertext,
                "env_key_generation": v.env_key_generation,
                "status": v.status,
            }
            for v in await session.scalars(select(SecretVersion))
        ]
    await engine.dispose()

    dump = tmp_path / "dump.sql"
    dump.write_text(
        "".join(
            _copy_block(name, rows)
            for name, rows in (
                ("projects", projects),
                ("environments", environments),
                ("env_keys", env_keys),
                ("secrets", secrets),
                ("secret_versions", versions),
            )
        ),
        encoding="utf-8",
    )

    tables = breakglass.read_tables(
        str(dump), {"projects", "environments", "env_keys", "secrets", "secret_versions"}
    )
    root = base64.b64decode(unsealed)
    values = breakglass.env_values(tables, root, env_id)
    assert [(name, value) for _path, name, value in values] == [
        ("DB_PASSWORD", "prod-пароль"),
        ("TOKEN", "две\nстроки"),
    ]


def test_breakglass_dump_says_e2e_plainly(tmp_path, capsys):
    """Проект с шифрованием в браузере: в дампе только блобы. Отдать их файлом
    .env значило бы подсунуть приложению "e2e:v1:..." вместо значений."""
    dump = tmp_path / "dump.sql"
    dump.write_text(
        "COPY public.projects (id, slug, group_slug, e2e) FROM stdin;\n"
        "1\tvault\t\tt\n"
        "2\tshop\t\tf\n"
        "\\.\n"
        "COPY public.environments (id, project_id, name, parent_id) FROM stdin;\n"
        "1\t1\tprod\t\\N\n"
        "2\t2\tprod\t\\N\n"
        "\\.\n",
        encoding="utf-8",
    )
    key = tmp_path / "root.key"
    key.write_text(base64.b64encode(b"k" * 32).decode(), encoding="utf-8")

    def args(**extra):
        base = dict(file=str(dump), password="", key_file=str(key), key="", share=[], list=False, env="")
        base.update(extra)
        return argparse.Namespace(**base)

    breakglass.cmd_dump(args(list=True))
    listed = capsys.readouterr().out
    assert "-/vault/prod" in listed and "vault/prod  (" in listed
    assert "-/shop/prod\n" in listed

    with pytest.raises(SystemExit) as stop:
        breakglass.cmd_dump(args(env="vault/prod"))
    assert "vault" in str(stop.value.code) and capsys.readouterr().out == ""


def test_breakglass_addresses_and_e2e_in_archive(monkeypatch, capsys):
    """Адрес "-/проект/окружение" из списка работает, одноименные проекты без
    группы в адресе - отказ, а окружение e2e не дает пустой .env."""
    data = {
        "created": "2026-10-12",
        "projects": [
            {"group": "acme", "slug": "shop", "environments": [
                {"name": "prod", "values": [{"path": "/", "name": "A", "value": "acme"}]}]},
            {"group": "", "slug": "shop", "environments": [
                {"name": "prod", "values": [{"path": "/", "name": "A", "value": "own"}]}]},
            {"group": "", "slug": "vault", "environments": [
                {"name": "prod", "values": [], "note": "шифрование в браузере"}]},
        ],
    }
    monkeypatch.setattr(breakglass, "_archive", lambda args: data)

    def env(address):
        breakglass.cmd_env(argparse.Namespace(address=address))
        return capsys.readouterr().out

    assert "A=own" in env("-/shop/prod")
    assert "A=acme" in env("acme/shop/prod")
    with pytest.raises(SystemExit) as stop:
        env("shop/prod")
    assert "acme" in str(stop.value.code)
    with pytest.raises(SystemExit):
        env("-/vault/prod")
    assert capsys.readouterr().out == ""

    breakglass.cmd_list(argparse.Namespace())
    listed = capsys.readouterr().out
    assert "-/vault/prod" in listed and "0" not in listed.split("-/vault/prod", 1)[1].splitlines()[0]


def test_breakglass_cli_takes_the_address_from_list(monkeypatch, capsys):
    """Адрес "-/проект/окружение" из list argparse принимал за ключ."""
    data = {
        "created": "2026-10-12",
        "projects": [
            {"group": "acme", "slug": "web", "environments": [
                {"name": "prod", "values": [{"path": "/", "name": "A", "value": "acme"}]}]},
            {"group": "", "slug": "web", "environments": [
                {"name": "prod", "values": [{"path": "/", "name": "A", "value": "own"}]}]},
        ],
    }
    monkeypatch.setattr(breakglass, "_archive", lambda args: data)
    monkeypatch.setattr(sys, "argv", ["breakglass.py", "env", "arch.sealed", "-/web/prod"])
    breakglass.main()
    assert "A=own" in capsys.readouterr().out


def test_breakglass_cli_keeps_option_values(monkeypatch):
    """Минус-слеш в начале значения пароля - это значение, а не адрес: молча
    превращать его в "/secret" нельзя (пароль "не подошел" бы непонятно
    почему). argparse такое значение без "=" не принимает и честно говорит об
    этом; через "--password=-/secret" оно доходит как есть."""
    seen = {}
    monkeypatch.setattr(breakglass, "cmd_open", lambda args: seen.update(vars(args)))
    monkeypatch.setattr(sys, "argv", ["breakglass.py", "open", "f.sealed", "--password", "-/secret"])
    with pytest.raises(SystemExit):
        breakglass.main()
    assert not seen
    monkeypatch.setattr(sys, "argv", ["breakglass.py", "open", "f.sealed", "--password=-/secret"])
    breakglass.main()
    assert seen["password"] == "-/secret"


def test_breakglass_env_quotes_multiline(capsys):
    breakglass.print_env([("/", "A", "две\nстроки"), ("/infra", "B", "простое")])
    printed = capsys.readouterr().out
    assert "A='две\nстроки'" in printed
    assert "B='простое'" in printed
    assert "# /infra" in printed


# --- оповещения ------------------------------------------------------------


async def test_alerts_masked_and_kept(client: httpx.AsyncClient, owner_headers):
    saved = await client.put(
        "/api/ops/alerts",
        headers=owner_headers,
        json={"telegram_token": "1234567890:секретный-токен", "telegram_chat": "-100500"},
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()
    # Токен наружу целиком не отдается никогда, даже владельцу.
    assert "секретный" not in json.dumps(body, ensure_ascii=False)
    assert body["enabled"] is True

    # Пустое поле не стирает канал: иначе сохранение соседней настройки
    # однажды выключило бы оповещения молча.
    again = await client.put(
        "/api/ops/alerts", headers=owner_headers, json={"telegram_chat": "-100777"}
    )
    assert again.json()["enabled"] is True
    assert again.json()["telegram_chat"] == "-100777"

    off = await client.put(
        "/api/ops/alerts", headers=owner_headers, json={"telegram_token": "-"}
    )
    assert off.json()["enabled"] is False


async def test_webhook_must_be_https_and_external(client: httpx.AsyncClient, owner_headers):
    for bad in (
        "http://example.com/hook",
        "https://127.0.0.1/hook",
        "https://10.0.0.5/hook",
        # RFC 6598: не частная по меркам ipaddress, но и не интернет
        "https://100.64.0.1/hook",
        "https://[::ffff:127.0.0.1]/hook",
        "https://example.com:99999/hook",
    ):
        res = await client.put("/api/ops/alerts", headers=owner_headers, json={"webhook": bad})
        assert res.status_code == 400, f"{bad}: {res.text}"


async def test_alerts_need_owner(client: httpx.AsyncClient, owner_headers):
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "keeper", "password": "keeper-pass-2026", "role": "maintainer"},
    )
    from tests.conftest import login

    headers = await login(client, "keeper", "keeper-pass-2026")
    assert (await client.get("/api/ops/alerts", headers=headers)).status_code == 403


async def test_test_button_needs_configured_channel(client: httpx.AsyncClient, owner_headers):
    res = await client.post("/api/ops/alerts/test", headers=owner_headers)
    assert res.status_code == 400


# --- копия журнала наружу --------------------------------------------------


async def test_audit_ship_batches_and_moves_cursor(client: httpx.AsyncClient, owner_headers):
    from app import audit_ship, settings_store

    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        rows = await audit_ship.pending(session, 0)
        assert rows, "в журнале уже должен быть хотя бы вход владельца"
        entry = audit_ship._entry(rows[0])
        # Наружу уезжают хеши: без них приемник не сможет доказать, что копия
        # соответствует цепочке.
        assert entry["chain"] and entry["prev_chain"] is not None
        await settings_store.put(session, audit_ship.CURSOR, str(rows[-1].id))
        await session.commit()
        assert await audit_ship.pending(session, rows[-1].id) == []
    await engine.dispose()


async def test_audit_ship_is_off_without_receiver(client: httpx.AsyncClient):
    from app import audit_ship

    engine, factory = create_engine_and_factory(get_settings().db_url)
    sent = await audit_ship.ship_once(factory, get_settings())
    await engine.dispose()
    assert sent == 0


# --- состояние бэкапа ------------------------------------------------------


async def test_backup_state_reads_the_mark(client: httpx.AsyncClient, owner_headers, tmp_path):
    from app import backups, config

    mark = tmp_path / "backup.json"
    mark.write_text(
        json.dumps({"at": "2020-01-01T00:00:00Z", "ok": True, "file": "x.sealed", "size": 10}),
        encoding="utf-8",
    )
    settings = get_settings()
    object.__setattr__(settings, "backup_state_file", str(mark))
    try:
        state = backups.read_state(settings)
        assert state.configured and state.ok
        # Отметка 2020 года - это молчание бэкапа, а молчание здесь и есть беда.
        assert state.stale is True
        assert "бэкапа нет" in backups.describe(state, settings)
    finally:
        object.__setattr__(settings, "backup_state_file", "")
        config.get_settings.cache_clear()


async def test_backup_state_without_setup(client: httpx.AsyncClient, owner_headers):
    res = await client.get("/api/ops/backup", headers=owner_headers)
    assert res.status_code == 200
    assert res.json()["configured"] is False
