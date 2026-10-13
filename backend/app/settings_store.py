"""Настройки, которые живут в базе, а не в .env.

Здесь то, что панель узнает о себе сама и должна помнить между перезапусками:
режим корневого ключа, его поколение, маркер проверки. Значения - строки; все
двоичное кладем в base64, чтобы таблица оставалась текстовой и читаемой глазами
при разборе инцидента.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AppSetting


async def get(session: AsyncSession, key: str, default: str = "") -> str:
    row = await session.get(AppSetting, key)
    return row.value if row is not None else default


async def get_many(session: AsyncSession, prefix: str) -> dict[str, str]:
    rows = await session.scalars(select(AppSetting).where(AppSetting.key.startswith(prefix)))
    return {r.key: r.value for r in rows}


async def put(session: AsyncSession, key: str, value: str) -> None:
    """Пишет значение. Коммит - на вызывающем: настройка почти всегда меняется
    вместе с чем-то еще (обертки ключей, запись в журнал), и разъехаться они не
    должны."""
    row = await session.get(AppSetting, key)
    if row is None:
        session.add(AppSetting(key=key, value=value))
    else:
        row.value = value
