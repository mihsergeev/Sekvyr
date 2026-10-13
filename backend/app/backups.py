"""Панель знает, когда её бэкапили в последний раз.

Бэкап снимает скрипт снаружи (`ops/backup.sh`), а не сама панель: дамп базы
делается тем же `pg_dump`, что и у всех, ходит по расписанию системного
таймера и не должен зависеть от того, поднялось ли приложение. Панель здесь
только читатель - скрипт оставляет отметку в файле, панель её показывает и
ругается, если отметка перестала обновляться.

Почему через файл, а не через API: скрипту обслуживания тогда не нужен ни
токен, ни сеть, ни живая панель. Файл лежит в томе данных, панель открывает его
на чтение - самая скучная связь из возможных, и она работает даже когда все
остальное сломано.

Молчание бэкапа - это происшествие. Не "диск заполнился" и не "упал контейнер",
а именно молчание: чаще всего бэкапы перестают делаться тихо, и обнаруживается
это в день, когда они понадобились.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app import alerts
from app.config import Settings

log = logging.getLogger("sekvyr.backups")

CHECK_INTERVAL = 1800  # раз в полчаса: событие суточного масштаба


@dataclass
class BackupState:
    configured: bool = False
    at: str = ""
    ok: bool = False
    file: str = ""
    size: int = 0
    detail: str = ""
    age_hours: float = -1.0
    stale: bool = False

    @property
    def alarming(self) -> bool:
        """Есть ли о чем сообщать: бэкап отвалился или последний был неудачным."""
        return self.configured and (self.stale or not self.ok)


def read_state(settings: Settings) -> BackupState:
    path = (settings.backup_state_file or "").strip()
    if not path:
        return BackupState()
    state = BackupState(configured=True)
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        state.detail = "отметки о бэкапе ещё нет"
        state.stale = True
        return state
    except (OSError, ValueError) as exc:
        state.detail = f"отметка не читается: {exc}"
        state.stale = True
        return state

    # Отметку пишет скрипт на хосте, и ее можно испортить руками: [] вместо
    # объекта или "12M" вместо числа роняли маршрут с 500, а наблюдатель за
    # бэкапом молча переставал тревожить.
    if not isinstance(raw, dict):
        state.detail = "отметка не читается: в ней не объект"
        state.stale = True
        return state
    try:
        state.size = int(raw.get("size", 0) or 0)
    except (TypeError, ValueError):
        state.size = 0
    state.at = str(raw.get("at", ""))
    state.ok = raw.get("ok") is True
    state.file = str(raw.get("file", ""))
    state.detail = str(raw.get("detail", ""))
    try:
        moment = datetime.fromisoformat(state.at.replace("Z", "+00:00"))
    except ValueError:
        state.detail = state.detail or "в отметке не разобрать время"
        state.stale = True
        return state
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    state.age_hours = (datetime.now(timezone.utc) - moment).total_seconds() / 3600
    state.stale = state.age_hours > settings.backup_max_age_hours
    return state


def describe(state: BackupState, settings: Settings) -> str:
    """Строка для оповещения. Возвращает пустую, если сообщать не о чем."""
    if not state.alarming:
        return ""
    if not state.ok and state.at:
        return f"🔥 Sekvyr: последний бэкап не удался ({state.detail or 'без подробностей'})"
    hours = int(state.age_hours)
    if hours < 0:
        return "🔥 Sekvyr: бэкапов ещё не было — отметка о них так и не появилась"
    return (
        f"🔥 Sekvyr: бэкапа нет уже {hours} ч "
        f"(порог {settings.backup_max_age_hours} ч) — восстанавливать сейчас нечего"
    )


async def watch(session_factory, settings: Settings) -> None:
    """Фоновая проверка отметки. Сообщает о поломке и о возврате в норму -
    по одному разу, а не на каждом круге."""
    import asyncio

    complained = False
    while True:
        try:
            state = read_state(settings)
            # "Сказано" - только после доставки, иначе тревога в лежащий канал
            # не повторялась бы до следующей поломки.
            if state.alarming and not complained:
                complained = await alerts.notify_later(session_factory, describe(state, settings))
            elif not state.alarming and complained:
                complained = not await alerts.notify_later(
                    session_factory, "🟢 Sekvyr: бэкапы снова снимаются"
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - наблюдатель не должен умирать
            log.warning("проверка отметки о бэкапе не удалась", exc_info=True)
        await asyncio.sleep(CHECK_INTERVAL)
