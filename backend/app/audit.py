"""Журнал действий с хеш-цепочкой.

Каждая запись хранит sha256 предыдущей и свой sha256, посчитанный вместе с ней.
Свойство простое: удалить или подправить строку в середине нельзя незаметно -
все последующие хеши перестают сходиться, и `verify()` показывает, с какой
записи цепочка разошлась.

Чего эта схема НЕ дает: она не мешает тому, у кого есть доступ к базе, срезать
журнал целиком с конца и продолжить писать заново. Против этого помогает копия
на чужом приемнике - она уезжает пачками в `app/audit_ship.py`; в самой базе
больше, чем цепочку, обещать нечего.

Значения секретов в журнал не попадают никогда - только факт обращения.
"""

import hashlib
from datetime import datetime, timezone

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog

GENESIS = "0" * 64  # prev_chain самой первой записи

# Ключ блокировки, под которой пишется журнал. Произвольное число, важно лишь
# что оно одно на всю панель: под ним выстраиваются в очередь все, кто хочет
# добавить запись.
_LOCK_KEY = 5_345_754_101

# Сколько записей проверка цепочки читает за раз.
VERIFY_BATCH = 2000


def to_utc(ts: datetime) -> datetime:
    """Момент времени в UTC.

    Записываем мы всегда aware-UTC, но обратно он приходит по-разному: Postgres
    отдает timestamptz с зоной, SQLite - "голый" datetime без нее. Такой naive
    нужно считать именно UTC: `astimezone` на нем подставил бы локальную зону
    машины, и пересчитанный хеш не сошелся бы с записанным. Ловится ровно на
    проверке цепочки, где выглядит как подделка журнала.
    """
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


def digest(
    *, ts: datetime, actor: str, action: str, target: str, detail: str, ip: str, prev: str
) -> str:
    """Хеш записи. Разделитель - \\x1f (unit separator): он не встречается в
    именах, адресах и комментариях, поэтому "склеить" два разных набора полей в
    одну и ту же строку не получится."""
    parts = (
        to_utc(ts).isoformat(),
        actor,
        action,
        target,
        detail,
        ip,
        prev,
    )
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


async def _lock(session: AsyncSession) -> None:
    """Блокировка журнала до конца транзакции (см. record). В SQLite (тесты)
    транзакции записи и так идут по одной."""
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _LOCK_KEY})


# Длина цели в журнале (столбец VARCHAR(200)). Кто сверяет строки журнала с
# ключами (непрочитанные, лента окружения), обрезает свою строку так же.
TARGET_MAX = 200


async def record(
    session: AsyncSession,
    actor: str,
    action: str,
    target: str = "",
    detail: str = "",
    ip: str = "",
) -> AuditLog:
    """Пишет запись и возвращает её. Коммит - на вызывающем: действие и его след
    в журнале должны попадать в базу одной транзакцией, иначе однажды случится
    успешное действие без записи о нем.

    Запись идет под блокировкой (`pg_advisory_xact_lock`), и это не украшение.
    Без нее две одновременные операции читают один и тот же последний хеш и
    получают одинаковый `prev_chain` - цепочка ветвится. Криптографически такое
    ветвление неотличимо от вырезанной записи, поэтому `verify()` честно
    объявляет журнал испорченным, а панель шлет тревогу на ровном месте. Один
    раз увиденная ложная тревога обесценивает все настоящие.

    Блокировка держится до конца транзакции вызывающего - того же самого, в
    которой уже идет действие. Своей транзакции журнал не открывает: запись о
    действии и само действие должны попадать в базу вместе или никак.
    """
    # Колонки автора, цели и адреса ограничены. Путь до 200 и имя до 200 дают
    # цель длиннее, и в Postgres это было "value too long", то есть 500 на любом
    # чтении и записи такого ключа. Обрезаем до размера колонки.
    actor, target, ip = actor[:64], target[:TARGET_MAX], ip[:64]
    # Изменения действия уходят в базу до блокировки журнала. Иначе одни
    # маршруты брали строку, а потом журнал (запись значения), другие - журнал,
    # а строку на коммите (правка окружения, машины, учетки), и Postgres
    # разрывал встречное ожидание, отменяя одну из транзакций.
    await session.flush()
    await _lock(session)
    prev = await session.scalar(select(AuditLog.chain).order_by(desc(AuditLog.id)).limit(1))
    prev = prev or GENESIS
    ts = datetime.now(timezone.utc)
    entry = AuditLog(
        ts=ts,
        actor=actor,
        action=action,
        target=target,
        detail=detail,
        ip=ip,
        prev_chain=prev,
        chain=digest(
            ts=ts, actor=actor, action=action, target=target, detail=detail, ip=ip, prev=prev
        ),
    )
    session.add(entry)
    return entry


async def verify(session: AsyncSession) -> tuple[bool, int | None, int]:
    """Проверяет цепочку целиком.

    Возвращает (все сошлось, id первой битой записи, число расхождений). Число
    нужно, чтобы отличать "одна строка не сходится" от "журнал переписан
    целиком": после первого разрыва пересчет продолжается от того, что записано,
    а не от того, что ожидалось - иначе одно расхождение делало бы битым весь
    оставшийся журнал и цифра ничего не значила бы.

    Журнал читается порциями и только нужными столбцами: целиком в память он
    поднимал бы сотни тысяч объектов ради одного прохода.
    """
    prev = GENESIS
    first: int | None = None
    breaks = 0
    last_id = 0
    columns = (
        AuditLog.id,
        AuditLog.ts,
        AuditLog.actor,
        AuditLog.action,
        AuditLog.target,
        AuditLog.detail,
        AuditLog.ip,
        AuditLog.prev_chain,
        AuditLog.chain,
    )
    while True:
        rows = (
            await session.execute(
                select(*columns)
                .where(AuditLog.id > last_id)
                .order_by(AuditLog.id)
                .limit(VERIFY_BATCH)
            )
        ).all()
        if not rows:
            break
        for row in rows:
            expected = digest(
                ts=row.ts,
                actor=row.actor,
                action=row.action,
                target=row.target,
                detail=row.detail,
                ip=row.ip,
                prev=prev,
            )
            if row.prev_chain != prev or row.chain != expected:
                breaks += 1
                if first is None:
                    first = row.id
            prev = row.chain
        last_id = rows[-1].id
    return breaks == 0, first, breaks
