import asyncio
import os
import subprocess
import sys
import threading
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from app import config

OWNER_PASSWORD = "owner-pass-2026"

# --- Postgres вместо SQLite (только для прогона на стенде) -----------------------
# SEKVYR_TEST_PG=postgresql+asyncpg://postgres:pw@host:5432 - без имени базы.
# SEKVYR_TEST_PG_SCHEMA=create_all | alembic - откуда берется схема шаблона.
# SEKVYR_TEST_PG_MAP=/out/dbmap.tsv - куда писать "база<TAB>тест" для разбора лога PG.
PG = os.environ.get("SEKVYR_TEST_PG", "").rstrip("/")
PG_SCHEMA = os.environ.get("SEKVYR_TEST_PG_SCHEMA", "create_all")
PG_MAP = os.environ.get("SEKVYR_TEST_PG_MAP", "")
BACKEND = Path(__file__).resolve().parent.parent
TEMPLATE = f"sekvyr_tpl_{PG_SCHEMA}"


def _raw_dsn(db: str) -> str:
    return PG.replace("postgresql+asyncpg://", "postgresql://", 1) + "/" + db


async def _admin(*statements: str) -> None:
    import asyncpg

    con = await asyncpg.connect(_raw_dsn("postgres"))
    try:
        for sql in statements:
            await con.execute(sql)
    finally:
        await con.close()


async def _build_template() -> None:
    await _admin(
        f'DROP DATABASE IF EXISTS "{TEMPLATE}" WITH (FORCE)',
        f'CREATE DATABASE "{TEMPLATE}"',
    )
    url = f"{PG}/{TEMPLATE}"
    if PG_SCHEMA == "alembic":
        env = dict(os.environ, SEKVYR_DB_URL=url, SEKVYR_JWT_SECRET="x" * 64)
        done = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=BACKEND, env=env, capture_output=True, text=True,
        )
        if done.returncode != 0:
            raise RuntimeError("alembic upgrade head: " + done.stderr[-4000:])
    else:
        from sqlalchemy.ext.asyncio import create_async_engine

        from app import models  # noqa: F401
        from app.db import Base

        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()


@pytest.fixture(scope="session")
def _pg_template():
    if not PG:
        return None
    errors: list[BaseException] = []

    def work() -> None:
        try:
            asyncio.run(_build_template())
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=work)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    return TEMPLATE


@pytest.fixture
async def client(tmp_path, monkeypatch, request, _pg_template) -> AsyncIterator[httpx.AsyncClient]:
    db_name = None
    if PG:
        db_name = "t_" + uuid.uuid4().hex[:16]
        await _admin(f'CREATE DATABASE "{db_name}" TEMPLATE "{_pg_template}"')
        if PG_MAP:
            with open(PG_MAP, "a", encoding="utf-8") as fh:
                fh.write(f"{db_name}\t{request.node.nodeid}\n")
        monkeypatch.setenv("SEKVYR_DB_URL", f"{PG}/{db_name}")
    else:
        db_path = (tmp_path / "test.db").as_posix()
        monkeypatch.setenv("SEKVYR_DB_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("SEKVYR_DATA_DIR", (tmp_path / "data").as_posix())
    monkeypatch.setenv("SEKVYR_ADMIN_USER", "owner")
    monkeypatch.setenv("SEKVYR_ADMIN_PASSWORD", OWNER_PASSWORD)
    monkeypatch.setenv("SEKVYR_JWT_SECRET", "test-secret-0123456789abcdef0123456789abcdef")
    config.get_settings.cache_clear()

    from app.bootstrap import ensure_owner
    from app.db import Base
    from app.main import create_app

    app = create_app()
    if not PG:
        async with app.state.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    await ensure_owner(app.state.session_factory, config.get_settings())

    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        await app.state.engine.dispose()
        config.get_settings.cache_clear()
        if db_name:
            await _admin(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')


async def login(client: httpx.AsyncClient, username: str, password: str) -> dict[str, str]:
    res = await client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


@pytest.fixture
async def owner_headers(client: httpx.AsyncClient) -> dict[str, str]:
    return await login(client, "owner", OWNER_PASSWORD)


@pytest.fixture
async def unsealed(client: httpx.AsyncClient, owner_headers: dict[str, str]) -> str:
    """Заведенный и распечатанный сейф в режиме переменной окружения.

    Режим `env`, а не доли: тестам нужен сам корневой ключ, чтобы проверять
    распечатывание после запечатывания, а собирать его из долей в каждом тесте -
    шум, который ничего не проверяет сверх test_shamir.
    """
    res = await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    assert res.status_code == 200, res.text
    return res.json()["root_key"]


@pytest.fixture
async def env_id(client: httpx.AsyncClient, owner_headers: dict[str, str], unsealed) -> int:
    """Проект billing с окружением prod - минимальное место, куда класть секреты."""
    res = await client.post(
        "/api/projects", headers=owner_headers, json={"slug": "billing", "title": "Биллинг"}
    )
    assert res.status_code == 201, res.text
    project_id = res.json()["id"]
    res = await client.post(
        f"/api/projects/{project_id}/environments",
        headers=owner_headers,
        json={"name": "prod"},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]
