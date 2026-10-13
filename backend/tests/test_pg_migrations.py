"""Миграции на настоящем Postgres: 0025 на данных старых версий и полный цикл вниз-вверх.

Только для прогона на стенде (SEKVYR_TEST_PG). Копия test_pass9_legacy для PG.
"""

import os
import subprocess
import sys
import uuid
from pathlib import Path

import asyncpg
import pytest

from tests.conftest import PG, _admin, _raw_dsn

BACKEND = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(not PG, reason="нужен SEKVYR_TEST_PG")


def _alembic(db: str, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, SEKVYR_DB_URL=f"{PG}/{db}", SEKVYR_JWT_SECRET="x" * 64)
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args], cwd=BACKEND, env=env, capture_output=True, text=True
    )


def _ok(done: subprocess.CompletedProcess) -> None:
    assert done.returncode == 0, done.stderr[-4000:]


@pytest.fixture
async def fresh_db():
    name = "m_" + uuid.uuid4().hex[:16]
    await _admin(f'CREATE DATABASE "{name}"')
    yield name
    await _admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


async def _insert(con: asyncpg.Connection, table: str, **values) -> int:
    rows = await con.fetch(
        "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = $1",
        table,
    )
    for row in rows:
        name = row["column_name"]
        if name in values or name == "id" or row["is_nullable"] == "YES" or row["column_default"] is not None:
            continue
        kind = row["data_type"]
        if kind in ("integer", "bigint", "smallint"):
            values[name] = 0
        elif kind == "boolean":
            values[name] = False
        elif kind.startswith("timestamp"):
            from datetime import datetime, timezone

            values[name] = datetime(2026, 1, 1, tzinfo=timezone.utc) if "with time zone" in kind else datetime(2026, 1, 1)
        else:
            values[name] = ""
    cols = ", ".join(f'"{c}"' for c in values)
    marks = ", ".join(f"${i + 1}" for i in range(len(values)))
    return await con.fetchval(f'INSERT INTO "{table}" ({cols}) VALUES ({marks}) RETURNING id', *values.values())


async def test_pg_migration_repairs_old_data(fresh_db):
    _ok(_alembic(fresh_db, "upgrade", "0024"))
    con = await asyncpg.connect(_raw_dsn(fresh_db))
    # Сирота на PG сама не возникает; ключи выключаем, чтобы проверить SQL ремонта на PG.
    await con.execute("SET session_replication_role = replica")
    env = await _insert(con, "environments", project_id=999, name="prod")
    await _insert(con, "env_keys", environment_id=env, generation=1, root_generation=1, active=True)
    lost = await _insert(con, "secrets", environment_id=env, path="/", name="OLD", current_version=1, deleted=False)
    await _insert(con, "secret_versions", secret_id=lost, version=1, name_at="OLD", path_at="/", status="current")
    await con.execute("SET session_replication_role = origin")
    project = await _insert(con, "projects", slug="live", title="", group_slug="", group_name="", e2e=False)
    live_env = await _insert(con, "environments", project_id=project, name="prod")
    key = await _insert(con, "secrets", environment_id=live_env, path="/", name="API_KEY", current_version=1, deleted=False)
    for version, status in ((1, "current"), (2, "pending"), (3, "current")):
        await _insert(con, "secret_versions", secret_id=key, version=version, name_at="API_KEY", path_at="/", status=status)
    await con.close()

    _ok(_alembic(fresh_db, "upgrade", "head"))
    con = await asyncpg.connect(_raw_dsn(fresh_db))
    assert await con.fetchval("SELECT count(*) FROM environments WHERE project_id = 999") == 0
    assert await con.fetchval("SELECT count(*) FROM secrets WHERE name = 'OLD'") == 0
    assert await con.fetchval("SELECT count(*) FROM secret_versions WHERE name_at = 'OLD'") == 0
    assert await con.fetchval("SELECT count(*) FROM env_keys WHERE environment_id = $1", env) == 0
    statuses = dict(await con.fetch("SELECT version, status FROM secret_versions WHERE secret_id = $1", key))
    assert statuses == {1: "superseded", 2: "rejected", 3: "current"}
    assert await con.fetchval("SELECT current_version FROM secrets WHERE id = $1", key) == 3
    await con.close()


async def test_pg_double_current_with_rename(fresh_db):
    """Две текущие, старшая под другим именем: ключ переезжает на имя старшей."""
    _ok(_alembic(fresh_db, "upgrade", "0024"))
    con = await asyncpg.connect(_raw_dsn(fresh_db))
    project = await _insert(con, "projects", slug="live", title="", group_slug="", group_name="", e2e=False)
    env = await _insert(con, "environments", project_id=project, name="prod")
    key = await _insert(con, "secrets", environment_id=env, path="/", name="OLD_NAME", current_version=1, deleted=False)
    await _insert(con, "secret_versions", secret_id=key, version=1, name_at="OLD_NAME", path_at="/", status="current")
    await _insert(con, "secret_versions", secret_id=key, version=2, name_at="NEW_NAME", path_at="/", status="current")
    await con.close()
    _ok(_alembic(fresh_db, "upgrade", "head"))
    con = await asyncpg.connect(_raw_dsn(fresh_db))
    row = await con.fetchrow("SELECT name, current_version, deleted FROM secrets WHERE id = $1", key)
    assert tuple(row) == ("NEW_NAME", 2, False)
    await con.close()


async def test_pg_machine_downgrade_takes_machine_rights_along(fresh_db):
    _ok(_alembic(fresh_db, "upgrade", "head"))
    con = await asyncpg.connect(_raw_dsn(fresh_db))
    project = await _insert(con, "projects", slug="p", title="", group_slug="", group_name="", e2e=False)
    await _insert(con, "policies", subject_type="machine", subject_id=1, project_id=project, path_prefix="/", actions="read", effect="allow")
    await _insert(con, "project_key_wraps", project_id=project, subject_type="machine", subject_id=1, nonce="n", wrapped_key="w")
    await con.close()
    _ok(_alembic(fresh_db, "downgrade", "0006"))
    _ok(_alembic(fresh_db, "upgrade", "head"))
    con = await asyncpg.connect(_raw_dsn(fresh_db))
    assert await con.fetchval("SELECT count(*) FROM policies WHERE subject_type = 'machine'") == 0
    assert await con.fetchval("SELECT count(*) FROM project_key_wraps WHERE subject_type = 'machine'") == 0
    await con.close()


async def test_pg_full_downgrade_and_upgrade(fresh_db):
    _ok(_alembic(fresh_db, "upgrade", "head"))
    _ok(_alembic(fresh_db, "downgrade", "base"))
    _ok(_alembic(fresh_db, "upgrade", "head"))


async def test_pg_alembic_check(fresh_db):
    _ok(_alembic(fresh_db, "upgrade", "head"))
    _ok(_alembic(fresh_db, "check"))
