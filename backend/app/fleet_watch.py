"""Панель замечает, что сервер перестал забирать секреты.

Про каждую машину известно, когда она приходила в последний раз: это видно
точкой в списке и отбором "молчат". Но смотреть в список серверов начинают
после того, как что-то сломалось, а сервер, замолчавший сутки назад, - это либо
мертвый агент, либо мертвый сервер, и правка, которую туда отправили, никуда не
доехала.

Сообщение уходит один раз на машину. Когда агент возвращается, панель забывает
о нем и в следующий раз скажет заново: "пропал и вернулся" - обычная жизнь
сервера, а вот "пропал, вернулся, снова пропал" стоит увидеть дважды.

Еженедельная сводка живет здесь же: она про тот же парк и про тот же канал.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import access, alerts, machines, settings_store
from app.audit import to_utc
from app.models import AuditLog, MachineIdentity, Policy

log = logging.getLogger("sekvyr.fleet")

# Раз в час: сутки молчания - не авария на минуты, но и ждать до утра незачем.
CHECK_INTERVAL = 60 * 60

# Сколько машина может молчать, прежде чем это станет новостью. Агент ходит раз
# в минуту, сутки тишины не объясняются ничем, кроме поломки.
SILENT_AFTER_HOURS = 24

# Где панель помнит, о каких машинах уже сказала: список идентификаторов через
# пробел. Отдельной таблицы ради этого заводить не стоит.
SILENT_KEY = "fleet_silent_seen"

# Сводка: раз в семь суток, по отметке о прошлой отправке.
DIGEST_KEY = "digest_sent_at"
DIGEST_EVERY = timedelta(days=7)

# Сколько строк показываем в сводке и в сообщении о молчащих.
IN_MESSAGE = 10


async def _granted(session: AsyncSession) -> set[int]:
    """Машины, которым хоть что-то выдано.

    Машина без единого права ничего не забирает и молчит по делу: сообщать о
    ней - значит учить людей пролистывать эти сообщения.
    """
    now = datetime.now(timezone.utc)
    rows = await session.scalars(select(Policy).where(Policy.subject_type == "machine"))
    # Истекшее право - то же, что никакого: машина молчит по плану.
    return {policy.subject_id for policy in rows if access.alive(policy, now)}


async def sweep_silent(session_factory) -> int:
    """Сообщить о машинах, которые молчат дольше положенного."""
    edge = datetime.now(timezone.utc) - timedelta(hours=SILENT_AFTER_HOURS)
    async with session_factory() as session:
        granted = await _granted(session)
        silent: list[tuple[int, str, datetime | None]] = []
        for machine in await session.scalars(select(MachineIdentity)):
            # Машина с вышедшим сроком молчит по плану (подрядчику дали до даты),
            # а не "перестала забирать секреты".
            if not machines.alive(machine) or machine.id not in granted:
                continue
            # Никогда не приходившая машина - это не "пропала", а "еще не
            # подключили": команду показывают в панели, и напоминать о ней
            # сообщением незачем.
            if machine.last_seen_at is None:
                continue
            if to_utc(machine.last_seen_at) > edge:
                continue
            silent.append((machine.id, machine.name, machine.last_seen_at))

        known = {
            int(part)
            for part in (await settings_store.get(session, SILENT_KEY, "")).split()
            if part.isdigit()
        }
        alive = {machine_id for machine_id, _name, _seen in silent}
        fresh = [item for item in silent if item[0] not in known]
        # Вернувшиеся забываем: если пропадет снова, скажем заново. Новые
        # молчащие запоминаются только после доставки сообщения (ниже).
        await settings_store.put(
            session, SILENT_KEY, " ".join(str(i) for i in sorted(alive & known))
        )
        await session.commit()

    if not fresh:
        return 0

    now = datetime.now(timezone.utc)
    lines = [f"🔌 Sekvyr: серверы перестали забирать секреты — {len(fresh)}"]
    for _machine_id, name, seen in fresh[:IN_MESSAGE]:
        hours = int((now - to_utc(seen)).total_seconds() // 3600) if seen else 0
        lines.append(f"{name} — молчит {hours} ч")
    if len(fresh) > IN_MESSAGE:
        lines.append(f"…и ещё {len(fresh) - IN_MESSAGE}")

    if not await alerts.notify_later(session_factory, "\n".join(lines)):
        return 0
    async with session_factory() as session:
        await settings_store.put(session, SILENT_KEY, " ".join(str(i) for i in sorted(alive)))
        await session.commit()
    return len(fresh)


# Действия, которые считаем правками значений: сводка про них, а не про чтения.
# Предложение (secret_pending) - еще не правка: приложения читают прежнее, и
# правкой оно станет при подтверждении (secret_approved). Раньше считалось
# предложение, а подтверждение нет, и неделя с двумя правками прода через
# подтверждение выглядела как тихая.
CHANGES = (
    "secret_written",
    "secret_deleted",
    "secret_rolled_back",
    "secret_renamed",
    "env_imported",
    "secret_approved",
    "secrets_migrated",
    "snapshot_restored",
    "secret_inherited",
    "env_copied",
)
# Смена родителя окружения меняет все унаследованные значения разом, а в
# журнале это правка окружения: отличаем ее по подробности.
REPARENT_MARK = "%родитель: %"


async def sweep_digest(session_factory) -> bool:
    """Раз в неделю - что менялось в панели. Возвращает, отправили ли сводку."""
    now = datetime.now(timezone.utc)
    async with session_factory() as session:
        last = await settings_store.get(session, DIGEST_KEY, "")
        if last:
            try:
                if now - datetime.fromisoformat(last) < DIGEST_EVERY:
                    return False
            except ValueError:
                pass
        else:
            # Первый запуск: отметку ставим, но сводку не шлем - иначе панель
            # здоровается письмом за неделю, которой еще не было.
            await settings_store.put(session, DIGEST_KEY, now.isoformat())
            await session.commit()
            return False

        since = now - DIGEST_EVERY
        rows = (
            await session.execute(
                select(AuditLog.actor, func.count())
                .where(
                    AuditLog.ts >= since,
                    AuditLog.action.in_(CHANGES)
                    | (
                        (AuditLog.action == "environment_updated")
                        & AuditLog.detail.like(REPARENT_MARK)
                    ),
                )
                .group_by(AuditLog.actor)
                .order_by(func.count().desc())
            )
        ).all()
        total = sum(count for _actor, count in rows)
        await settings_store.put(session, DIGEST_KEY, now.isoformat())
        await session.commit()

    if total == 0:
        # Тихая неделя - тоже новость, но не та, ради которой стоит писать.
        return False

    lines = [f"🗓 Sekvyr: за неделю правок значений — {total}"]
    for actor, count in rows[:IN_MESSAGE]:
        lines.append(f"{actor or 'кто-то'} — {count}")
    if len(rows) > IN_MESSAGE:
        lines.append(f"…и ещё {len(rows) - IN_MESSAGE}")

    await alerts.notify_later(session_factory, "\n".join(lines))
    return True


async def watch(session_factory) -> None:
    """Фоновый присмотр за парком: молчащие агенты и недельная сводка."""
    while True:
        try:
            count = await sweep_silent(session_factory)
            if count:
                log.info("замолчавших серверов: %s", count)
            if await sweep_digest(session_factory):
                log.info("недельная сводка отправлена")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - присмотр не должен ронять панель
            log.warning("присмотр за парком не удался", exc_info=True)
        await asyncio.sleep(CHECK_INTERVAL)
