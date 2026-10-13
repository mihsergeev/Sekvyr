"""Панель сама проверяет цепочку журнала раз в сутки.

Раньше цепочку пересчитывала только кнопка в разделе журнала, и оповещение о
правке журнала в обход панели уходило, только если кто-то ее нажал. Теперь
проверка идет раз в сутки, а сообщение уходит, когда картина изменилась:
другая первая битая запись или другое число расхождений. Одно и то же
расхождение каждые сутки - не новость, а шум, который учит пролистывать
сообщения.
"""

from __future__ import annotations

import asyncio
import logging

from app import alerts, audit, settings_store

log = logging.getLogger("sekvyr.audit")

CHECK_INTERVAL = 24 * 60 * 60
# Первая проверка не в первые минуты после старта: панель только поднялась, и
# пересчет всего журнала подождет, пока она отвечает на первые запросы.
START_DELAY = 10 * 60
# Что проверка увидела в прошлый раз: "ok" или "<первая битая> <расхождений>".
STATE_KEY = "audit_verify_state"


async def sweep(session_factory) -> bool:
    """Пересчитать цепочку. Возвращает, ушло ли сообщение."""
    async with session_factory() as session:
        ok, first, breaks = await audit.verify(session)
        state = "ok" if ok else f"{first} {breaks}"
        known = await settings_store.get(session, STATE_KEY, "")
        if ok or state == known:
            await settings_store.put(session, STATE_KEY, state)
            await session.commit()
            return False
    # Состояние запоминается только после доставки: тревога о правке журнала
    # в обход панели, ушедшая в лежащий канал, иначе не повторялась бы.
    if not await alerts.notify_later(
        session_factory,
        f"🚨 Sekvyr: журнал не сходится начиная с записи №{first} "
        f"(расхождений: {breaks}) — записи правили в обход панели",
    ):
        return False
    async with session_factory() as session:
        await settings_store.put(session, STATE_KEY, state)
        await session.commit()
    return True


async def watch(session_factory) -> None:
    """Фоновая проверка журнала."""
    await asyncio.sleep(START_DELAY)
    while True:
        try:
            if await sweep(session_factory):
                log.warning("цепочка журнала не сходится")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - проверка не должна ронять панель
            log.warning("проверка журнала не удалась", exc_info=True)
        await asyncio.sleep(CHECK_INTERVAL)
