from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import Request
from sqlalchemy import event, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm.attributes import set_committed_value


class Base(DeclarativeBase):
    pass


async def bump_token_version(session: AsyncSession, obj) -> None:
    """token_version + 1 в самой базе, а не по загруженному значению.

    Два одновременных отзыва (смена роли и отключение, смена пароля и сброс)
    иначе оба писали "прочитанное + 1", одно увеличение терялось, и токен,
    выданный между ними, переживал отзыв.
    """
    model = type(obj)
    fresh = await session.scalar(
        update(model)
        .where(model.id == obj.id)
        .values(token_version=model.token_version + 1)
        .returning(model.token_version)
        .execution_options(synchronize_session=False)
    )
    set_committed_value(obj, "token_version", fresh)


def ensure_sqlite_dir(db_url: str) -> None:
    """Создает каталог для файла sqlite.

    Нужно в двух местах: при подъеме приложения и при миграциях. Alembic ходит
    в базу мимо create_engine_and_factory, и без этого `alembic upgrade head` на
    свежей копии падал "unable to open database file" - сообщение, по которому
    не догадаться, что не хватает каталога.
    """
    url = make_url(db_url)
    if url.get_backend_name() == "sqlite" and url.database and url.database != ":memory:":
        Path(url.database).parent.mkdir(parents=True, exist_ok=True)


def enforce_sqlite_foreign_keys(engine: AsyncEngine) -> None:
    """Внешние ключи в SQLite по умолчанию выключены, и каждое соединение
    включает их само.

    Без этого ни одно ondelete="CASCADE" не срабатывало: удаленный снимок
    оставлял свои строки, SQLite отдавал освободившийся номер следующему
    снимку, и тот падал с 500 на чужих строках (нашел фаззинг). Хуже того,
    тесты на SQLite не видели нарушений ключей, которые Postgres в работе
    отверг бы.
    """
    if engine.dialect.name != "sqlite":
        return

    @event.listens_for(engine.sync_engine, "connect")
    def _foreign_keys_on(dbapi_connection, _record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def create_engine_and_factory(
    db_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    ensure_sqlite_dir(db_url)
    engine = create_async_engine(db_url)
    enforce_sqlite_foreign_keys(engine)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.session_factory() as session:
        yield session
