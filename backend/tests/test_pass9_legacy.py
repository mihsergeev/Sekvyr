"""Девятый проход: данные, оставленные версиями до 1.0.0.

Новый код таких состояний не создает, поэтому они заводятся прямо в базе: две
текущие версии, версия под удаленным поколением ключа, имя ключа по прежним
правилам, сироты SQLite.
"""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx
from sqlalchemy import text

from app import emergency, secrets_store
from app.api.secrets import _hide_closed_place
from app.main import LOST_KEY

BACKEND = Path(__file__).resolve().parent.parent


async def _put(client, h, env, name, value, path="/"):
    res = await client.put(f"/api/environments/{env}/secrets", headers=h, json={"name": name, "value": value, "path": path})
    assert res.status_code == 200, res.text


async def _sql(client, statement, **params):
    app = client._transport.app
    async with app.state.session_factory() as session:
        await session.execute(text(statement), params)
        await session.commit()


async def test_a_version_under_a_lost_key_explains_itself(client: httpx.AsyncClient, owner_headers, env_id):
    h = owner_headers
    await _put(client, h, env_id, "K", "v")
    await _put(client, h, env_id, "OTHER", "o")
    await _sql(client, "UPDATE secret_versions SET env_key_generation = 99 WHERE name_at = 'K'")
    res = await client.get(f"/api/environments/{env_id}/secret", headers=h, params={"name": "K"})
    assert res.status_code == 500 and res.json()["detail"] == LOST_KEY
    # Смена ключа окружения не падает навсегда: нечитаемую версию оставляет.
    res = await client.post(f"/api/environments/{env_id}/rotate-key", headers=h)
    assert res.status_code == 200, res.text
    assert (await client.get(f"/api/environments/{env_id}/secret", headers=h, params={"name": "OTHER"})).json()["value"] == "o"
    # Аварийный архив не теряет остальные значения из-за одного.
    app = client._transport.app
    async with app.state.session_factory() as session:
        data = await emergency.collect(session, app.state.sealbox)
    env = data["projects"][0]["environments"][0]
    assert [v["name"] for v in env["values"]] == ["OTHER"]
    assert env["unreadable"] == ["/:K"]


async def test_two_current_versions_give_the_newest(client: httpx.AsyncClient, owner_headers, env_id):
    h = owner_headers
    await _put(client, h, env_id, "API_KEY", "v1")
    await _put(client, h, env_id, "API_KEY", "v2")
    await _sql(client, "UPDATE secret_versions SET status = 'current'")
    await _put(client, h, env_id, "API_KEY", "fresh-after-upgrade")
    res = await client.get(f"/api/environments/{env_id}/secret", headers=h, params={"name": "API_KEY"})
    assert res.json()["value"] == "fresh-after-upgrade"


async def test_old_names_stay_away_from_machines(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    h = owner_headers
    real = secrets_store.check_name
    monkeypatch.setattr(secrets_store, "check_name", lambda name, **_kw: None)
    await _put(client, h, env_id, "smtp/host", "mail")
    monkeypatch.setattr(secrets_store, "check_name", real)
    await _put(client, h, env_id, "GOOD", "1")
    machine = (await client.post("/api/machines", headers=h, json={"name": "node", "description": ""})).json()
    await client.post(
        "/api/policies",
        headers=h,
        json={"subject_type": "machine", "subject_id": machine["id"], "environment_id": env_id,
              "path_prefix": "/", "actions": ["read", "list"], "effect": "allow"},
    )
    token = (await client.post("/api/v1/machine/token", json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]})).json()["access_token"]
    res = await client.get("/api/v1/machine/env", headers={"Authorization": "Bearer " + token}, params={"project": "billing", "env": "prod"})
    assert res.status_code == 200, res.text
    body = res.text
    assert "GOOD" in body and "smtp/host" not in body
    # Значение под старым именем не правится, но переименовать ключ можно.
    res = await client.put(f"/api/environments/{env_id}/secrets", headers=h, json={"name": "smtp/host", "value": "x"})
    assert res.status_code == 400
    res = await client.post(f"/api/environments/{env_id}/secret/rename", headers=h, json={"name": "smtp/host", "new_name": "SMTP_HOST"})
    assert res.status_code == 200, res.text


def test_event_hides_a_closed_folder_written_without_slash():
    closed = lambda path: path != "/private"  # noqa: E731
    assert _hide_closed_place("было private:RAW", closed) == "было в закрытой папке"
    assert _hide_closed_place("было /public:RAW", closed) == "было /public:RAW"


# --- миграция 0025 на SQLite -----------------------------------------------------


def _alembic(db: Path, *args: str) -> None:
    env = dict(os.environ, SEKVYR_DB_URL=f"sqlite+aiosqlite:///{db.as_posix()}", SEKVYR_JWT_SECRET="x" * 64)
    done = subprocess.run(
        [sys.executable, "-m", "alembic", *args], cwd=BACKEND, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    assert done.returncode == 0, done.stderr[-2000:]


def _insert(con: sqlite3.Connection, table: str, **values) -> int:
    """Строка с заданными полями; обязательные без умолчания - пустышками."""
    for _cid, name, kind, notnull, default, pk in con.execute(f"PRAGMA table_info({table})"):
        if name in values or pk or not notnull or default is not None:
            continue
        kind = (kind or "").upper()
        values[name] = 0 if ("INT" in kind or "BOOL" in kind) else ("2026-01-01 00:00:00" if "DATE" in kind else "")
    cols = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    return con.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(values.values())).lastrowid


def test_migration_repairs_old_data(tmp_path):
    db = tmp_path / "old.db"
    _alembic(db, "upgrade", "0024")
    con = sqlite3.connect(db)  # внешние ключи выключены, как в старых версиях
    # Сирота: окружение удаленного проекта со своими строками.
    env = _insert(con, "environments", project_id=999, name="prod")
    _insert(con, "env_keys", environment_id=env, generation=1, root_generation=1, active=True)
    lost = _insert(con, "secrets", environment_id=env, path="/", name="OLD", current_version=1, deleted=False)
    _insert(con, "secret_versions", secret_id=lost, version=1, name_at="OLD", path_at="/", status="current")
    # Живой проект: две текущие версии и устаревшая ожидающая правка.
    project = _insert(con, "projects", slug="live", title="", group_slug="", group_name="", e2e=False)
    live_env = _insert(con, "environments", project_id=project, name="prod")
    key = _insert(con, "secrets", environment_id=live_env, path="/", name="API_KEY", current_version=1, deleted=False)
    for version, status in ((1, "current"), (2, "pending"), (3, "current")):
        _insert(con, "secret_versions", secret_id=key, version=version, name_at="API_KEY", path_at="/", status=status)
    con.commit()
    con.close()

    _alembic(db, "upgrade", "head")
    con = sqlite3.connect(db)
    assert con.execute("SELECT count(*) FROM environments WHERE project_id = 999").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM secrets WHERE name = 'OLD'").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM secret_versions WHERE name_at = 'OLD'").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM env_keys WHERE environment_id = ?", (env,)).fetchone()[0] == 0
    statuses = dict(con.execute("SELECT version, status FROM secret_versions WHERE secret_id = ?", (key,)).fetchall())
    assert statuses == {1: "superseded", 2: "rejected", 3: "current"}
    assert con.execute("SELECT current_version FROM secrets WHERE id = ?", (key,)).fetchone()[0] == 3
    con.close()


def test_machine_downgrade_takes_machine_rights_along(tmp_path):
    db = tmp_path / "cycle.db"
    _alembic(db, "upgrade", "head")
    con = sqlite3.connect(db)
    project = _insert(con, "projects", slug="p", title="", group_slug="", group_name="", e2e=False)
    _insert(con, "policies", subject_type="machine", subject_id=1, project_id=project, path_prefix="/", actions="read", effect="allow")
    _insert(con, "project_key_wraps", project_id=project, subject_type="machine", subject_id=1, nonce="n", wrapped_key="w")
    con.commit()
    con.close()
    _alembic(db, "downgrade", "0006")
    _alembic(db, "upgrade", "head")
    con = sqlite3.connect(db)
    assert con.execute("SELECT count(*) FROM policies WHERE subject_type = 'machine'").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM project_key_wraps WHERE subject_type = 'machine'").fetchone()[0] == 0
    con.close()
