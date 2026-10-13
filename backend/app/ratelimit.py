"""Лимитер попыток входа.

Счетчик лежит в базе, а не в памяти процесса: панель может работать несколькими
воркерами uvicorn, и у каждого был бы свой словарь - порог тогда умножается на
число процессов, причем молча. Снаружи защита при этом выглядит рабочей: часть
попыток честно получает 429.

Ключ - адрес клиента, а у IPv6 вся его сеть /64: столько провайдер выдает
одному абоненту, и без этого каждый новый адрес из нее начинал бы счет с нуля.
При превышении порога вход блокируется на время окна.
"""

import ipaddress
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import LoginFailure

WINDOW = 300  # сек: окно подсчета неудачных попыток
MAX_FAILURES = 10  # неудач в окне до блокировки
LOCKOUT = 900  # сек: после этого запись уже не попадет ни в одно окно


def subject(ip: str) -> str:
    """Чей это адрес для лимитера: IPv4 как есть, IPv6 - его сеть /64."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return ip


def _now(now: float | None) -> datetime:
    return datetime.fromtimestamp(time.time() if now is None else now, tz=timezone.utc)


async def _recent(session: AsyncSession, key: str, moment: datetime) -> int:
    return int(await session.scalar(
        select(func.count())
        .select_from(LoginFailure)
        .where(LoginFailure.key == key, LoginFailure.ts >= moment - timedelta(seconds=WINDOW))
    ) or 0)


async def is_locked(
    session: AsyncSession, key: str, *, now: float | None = None, limit: int = MAX_FAILURES
) -> bool:
    return await _recent(session, key, _now(now)) >= limit


async def _rank(session: AsyncSession, key: str, moment: datetime, row_id: int) -> int:
    """Место записи в окне по порядку вставки. По общему счету два одновременных
    коммита оба видели 11 при пороге 10, и оповещение не уходило вовсе."""
    return int(await session.scalar(
        select(func.count())
        .select_from(LoginFailure)
        .where(
            LoginFailure.key == key,
            LoginFailure.ts >= moment - timedelta(seconds=WINDOW),
            LoginFailure.id <= row_id,
        )
    ) or 0)


async def _add(session: AsyncSession, key: str, moment: datetime) -> LoginFailure:
    row = LoginFailure(key=key, ts=moment)
    session.add(row)
    # чистим то, что уже никогда не попадет в окно, - таблица не растет
    await session.execute(
        delete(LoginFailure).where(LoginFailure.ts < moment - timedelta(seconds=LOCKOUT))
    )
    await session.commit()
    return row


async def record_failure(
    session: AsyncSession, key: str, *, now: float | None = None, limit: int = MAX_FAILURES
) -> bool:
    """Регистрирует неудачу. True, если ИМЕННО эта попытка включила блокировку -
    чтобы уведомление ушло один раз, а не на каждую следующую попытку."""
    moment = _now(now)
    row = await _add(session, key, moment)
    return await _rank(session, key, moment, row.id) == limit


@dataclass
class Attempt:
    id: int
    # Эта попытка, если не удастся, включает блокировку: оповещение - по ней.
    closes: bool


async def attempt(
    session: AsyncSession, key: str, *, now: float | None = None, limit: int = MAX_FAILURES
) -> Attempt | None:
    """Попытка идет в счет ДО проверки. None - порог уже пройден.

    Проверка "заперто ли" и учет неудачи после bcrypt разнесены во времени, и
    пачка одновременных запросов проходила проверку целиком: двадцать паролей
    при пороге в десять. Теперь запись ставится первой, а решает её место в
    окне. Удачная попытка свою запись снимает (forget).
    """
    moment = _now(now)
    row = await _add(session, key, moment)
    rank = await _rank(session, key, moment, row.id)
    if rank > limit:
        # Ее не проверяли: в счете неудач ей не место (иначе пачка верных
        # входов из одного офиса запирала адрес на окно).
        await forget(session, Attempt(row.id, False))
        return None
    return Attempt(row.id, rank == limit)


async def forget(session: AsyncSession, attempt: Attempt) -> None:
    await session.execute(delete(LoginFailure).where(LoginFailure.id == attempt.id))
    await session.commit()


async def clear(session: AsyncSession, key: str) -> None:
    await session.execute(delete(LoginFailure).where(LoginFailure.key == key))
    await session.commit()
