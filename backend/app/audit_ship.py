"""Вынос журнала наружу: копия записей уезжает на чужой приемник.

Хеш-цепочка внутри базы ловит правку и удаление в середине, но не спасает от
того, у кого есть база целиком: журнал можно срезать с конца и продолжить с
новой "генезисной" записи. Единственная защита от этого - копия там, куда
владелец базы не дотягивается.

Как устроено. Фоновая задача раз в `audit_ship_interval` секунд берет записи
новее отправленных и шлет их пачкой на вебхук вместе с их хешами. Курсор лежит
в настройках панели: после перезапуска отправка продолжается с того места, где
остановилась, а не начинается заново и не теряет хвост.

Почему пачкой и по таймеру, а не в момент записи: запись в журнал идет внутри
транзакции действия, и синхронная отправка означала бы, что медленный приемник
задерживает выдачу секрета, а недоступный - откатывает действие. Журнал не
должен становиться причиной отказа.

Что видит приемник: id, время, кто, что, над чем, адрес и оба хеша. Значений
секретов в журнале нет по построению, так что наружу они не уезжают и здесь.
"""

from __future__ import annotations

import asyncio
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import alerts, settings_store
from app.audit import to_utc
from app.config import Settings
from app.models import AuditLog

log = logging.getLogger("sekvyr.audit_ship")

CURSOR = "audit_shipped_id"
BATCH = 200


def _entry(row: AuditLog) -> dict:
    return {
        "id": row.id,
        "ts": to_utc(row.ts).isoformat(),
        "actor": row.actor,
        "action": row.action,
        "target": row.target,
        "detail": row.detail,
        "ip": row.ip,
        "prev_chain": row.prev_chain,
        "chain": row.chain,
    }


async def pending(session: AsyncSession, cursor: int, limit: int = BATCH) -> list[AuditLog]:
    rows = await session.scalars(
        select(AuditLog).where(AuditLog.id > cursor).order_by(AuditLog.id).limit(limit)
    )
    return list(rows)


async def ship_once(session_factory, settings: Settings, panel: str = "") -> int:
    """Одна отправка. Возвращает число уехавших записей.

    Курсор двигаем ТОЛЬКО после успешного ответа приемника: лучше отправить
    запись дважды (у нее есть id, приемник разберется), чем потерять её из-за
    сетевой ошибки.
    """
    async with session_factory() as session:
        cfg = await alerts.get_config(session, settings)
        url = cfg.get("audit_webhook")
        if not url:
            return 0
        cursor = int(await settings_store.get(session, CURSOR, "0") or 0)
        rows = await pending(session, cursor)
        if not rows:
            return 0
        body = {"panel": panel, "entries": [_entry(row) for row in rows]}

    async with httpx.AsyncClient(timeout=15) as http:
        response = await http.post(url, json=body)
        response.raise_for_status()

    async with session_factory() as session:
        await settings_store.put(session, CURSOR, str(rows[-1].id))
        await session.commit()
    return len(rows)


async def run(session_factory, settings: Settings) -> None:
    """Фоновый цикл. Живет, пока жива панель; о поломке сообщает один раз.

    Один раз - потому что упавший приемник журнала это состояние, а не поток
    событий: повторять о нем каждые полминуты значит приучить читателя гасить
    оповещения панели вообще.
    """
    complained = False
    while True:
        try:
            sent = await ship_once(session_factory, settings, settings.panel_url)
            if sent and complained:
                complained = False
                await alerts.notify_later(
                    session_factory, "🟢 Sekvyr: журнал снова уезжает на приёмник"
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - цикл не должен умирать
            log.warning("журнал не уехал: %s", exc)
            if not complained:
                complained = True
                await alerts.notify_later(
                    session_factory,
                    "🔥 Sekvyr: копия журнала не уходит на приёмник — "
                    "внешней копии записей сейчас нет",
                )
        await asyncio.sleep(max(5, settings.audit_ship_interval))
