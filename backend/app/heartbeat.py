"""Пульс панели: файл, по которому сторож снаружи понимает, жива ли она.

Панель не может сообщить о собственной смерти собственным же каналом. Нужен
наблюдатель вне процесса, и чтобы он мог позвать на помощь, ему нужны две вещи:
признак жизни и реквизиты канала. И то и другое лежит в одном файле, который
панель переписывает раз в минуту.

Почему файл, а не запрос к `/api/health`: контейнер может отвечать "ок" на
здоровье и при этом не иметь базы, а сторожу важно ровно обратное - что панель
дошла до базы, прочитала настройки и осталась в сознании. Плюс файл читается,
когда HTTP уже не отвечает вовсе.

Про реквизиты в файле честно: токен бота лежит на диске рядом с панелью,
правами 0600. Тот, кто добрался до этого файла, добрался и до базы; ценность
токена - право написать в один чат, а цена отказа от него - сторож, который в
день аварии не может сказать ни слова.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from time import time

import httpx

from app import alerts
from app.config import Settings

log = logging.getLogger("sekvyr.heartbeat")

INTERVAL = 60  # писать раз в минуту
SELFTEST_EVERY = 30  # проверять канал раз в полчаса циклов


def path_for(settings: Settings) -> Path:
    return Path(settings.data_dir) / "heartbeat"


def write(settings: Settings, cfg: dict, *, sealed: bool, alerts_ok: int) -> None:
    """Переписывает файл пульса. Пишем через временный файл и переименование:
    сторож не должен однажды прочитать полуготовую строку."""
    target = path_for(settings)
    target.parent.mkdir(parents=True, exist_ok=True)

    def one_line(value: object) -> str:
        # Перевод строки в токене дописал бы сторожу свою строку
        # "tg_api=http://127.0.0.1:..." мимо проверки адресов: сторож берет
        # первую найденную строку с нужным именем.
        return str(value).replace("\r", "").replace("\n", "")

    lines = [
        f"ts={int(time())}",
        f"panel={one_line(settings.panel_url)}",
        f"sealed={1 if sealed else 0}",
        f"alerts_ok={alerts_ok}",
        f"tg_token={one_line(cfg.get('telegram_token', ''))}",
        f"tg_chat={one_line(cfg.get('telegram_chat', ''))}",
        f"tg_api={one_line(cfg.get('telegram_api', ''))}",
        f"webhook={one_line(cfg.get('webhook', ''))}",
    ]
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.replace(tmp, target)


async def _selftest(cfg: dict) -> int:
    """Жив ли канал Telegram. 1 - да, 0 - нет, -1 - проверять нечего.

    Спрашиваем `getMe`, а не шлем сообщение: проверка не должна будить людей.
    Вебхук не трогаем вовсе - у чужого приемника нет способа сказать "я здесь"
    так, чтобы это не выглядело событием. О нем говорит итог последней
    настоящей отправки, см. channel_state.
    """
    token = cfg.get("telegram_token")
    if not (token and cfg.get("telegram_chat")):
        return -1
    base = (cfg.get("telegram_api") or "https://api.telegram.org").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10) as http:
            response = await http.get(f"{base}/bot{token}/getMe")
        return 1 if response.status_code == 200 else 0
    except Exception:  # noqa: BLE001 - недоступность и есть ответ
        return 0


def channel_state(selftest: int) -> int:
    """Канал оповещений для пульса: 1 - жив, 0 - сломан, -1 - неизвестно.

    Telegram проверяется getMe, вебхук так не проверить, и о нем судим по
    последней настоящей отправке. Без этого панель с одним вебхуком никогда не
    сообщала сторожу о поломке канала: проверка возвращала "проверять нечего",
    и мертвый приемник оставался незамеченным. Не дошло хоть куда-то - канал
    сломан, пока следующая отправка (или кнопка проверки) не пройдет.
    """
    if selftest == 0 or alerts.last_delivery is False:
        return 0
    if selftest == 1 or alerts.last_delivery is True:
        return 1
    return -1


async def run(session_factory, settings: Settings, box) -> None:
    """Фоновый цикл: пишет пульс, изредка проверяя канал оповещений."""
    selftest = -1
    tick = 0
    while True:
        try:
            async with session_factory() as session:
                cfg = await alerts.get_config(session, settings)
            if tick % SELFTEST_EVERY == 0:
                selftest = await _selftest(cfg)
            write(settings, cfg, sealed=not box.unsealed, alerts_ok=channel_state(selftest))
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - пульс не должен ронять панель
            log.warning("пульс не записан", exc_info=True)
        tick += 1
        await asyncio.sleep(INTERVAL)
