"""Оповещения: Telegram и вебхук.

Панель с секретами молчать не должна. События, ради которых это написано, -
не "нагрузка выросла", а "кто-то распечатал сейф", "вход заблокирован после
серии неудачных попыток", "собран аварийный архив со всеми значениями". Такие
вещи узнают вовремя или не узнают вовсе.

Два решения, которые стоит объяснить.

**Настройки лежат в базе открытым текстом, а не под корневым ключом.** Соблазн
зашифровать токен велик, но тогда панель, поднявшаяся запертой, не сможет
сказать об этом ни одному человеку: чтобы прочитать токен, ей нужен ключ,
которого у нее нет. Оповещение "панель заперта и ждет долей" важнее, чем
защита токена бота от того, кто и так добрался до базы. Токен бота - не ключ от
секретов, а право писать в один чат.

**Отправка не мешает делу.** Любая ошибка канала гасится и пишется в лог: не
доставленное оповещение не должно откатывать транзакцию, из-за которой оно
возникло. Обратная сторона - оповещения не гарантированы, и на них нельзя
строить учет; для учета есть журнал.
"""

from __future__ import annotations

import asyncio
import html
import logging

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_store
from app.config import Settings, get_settings

log = logging.getLogger("sekvyr.alerts")

# Итог последней настоящей отправки: True - дошло во все каналы, False - хотя
# бы в один не дошло, None - отправок еще не было. Вебхук не проверить, не
# послав сообщения, поэтому о его поломке пульс узнает только отсюда.
last_delivery: bool | None = None

TELEGRAM_TOKEN = "alert_telegram_token"
TELEGRAM_CHAT = "alert_telegram_chat"
TELEGRAM_API = "alert_telegram_api"
WEBHOOK = "alert_webhook"
AUDIT_WEBHOOK = "audit_webhook"


async def get_config(session: AsyncSession, settings: Settings | None = None) -> dict:
    """Действующие настройки: что задано в панели, иначе - что пришло из `.env`.

    Значения из окружения - это то же, чем пользуются скрипты обслуживания
    (`ops/backup.sh`, `ops/panel-watchdog.sh`): сторож должен уметь позвать на
    помощь, когда панели уже нет и спросить настройки не у кого.
    """
    settings = settings or get_settings()
    stored = await settings_store.get_many(session, "alert_")
    audit_stored = await settings_store.get(session, AUDIT_WEBHOOK, "")
    return {
        "telegram_token": stored.get(TELEGRAM_TOKEN) or settings.alert_telegram_token,
        "telegram_chat": stored.get(TELEGRAM_CHAT) or settings.alert_telegram_chat,
        # Зеркало Bot API: для сетей, где api.telegram.org недоступен.
        "telegram_api": stored.get(TELEGRAM_API) or settings.alert_telegram_api,
        "webhook": stored.get(WEBHOOK) or settings.alert_webhook,
        "audit_webhook": audit_stored or settings.audit_webhook,
    }


async def set_config(
    session: AsyncSession,
    *,
    telegram_token: str,
    telegram_chat: str,
    telegram_api: str,
    webhook: str,
    audit_webhook: str,
) -> None:
    await settings_store.put(session, TELEGRAM_TOKEN, telegram_token.strip())
    await settings_store.put(session, TELEGRAM_CHAT, telegram_chat.strip())
    await settings_store.put(session, TELEGRAM_API, telegram_api.strip().rstrip("/"))
    await settings_store.put(session, WEBHOOK, webhook.strip())
    await settings_store.put(session, AUDIT_WEBHOOK, audit_webhook.strip())


def enabled(cfg: dict) -> bool:
    return bool((cfg.get("telegram_token") and cfg.get("telegram_chat")) or cfg.get("webhook"))


def _redact(text: str, *secrets: str) -> str:
    for item in secrets:
        if item and len(item) >= 8:
            text = text.replace(item, "***")
    return text


def _error_text(exc: Exception, *secrets: str) -> str:
    """Короткое описание ошибки БЕЗ секретов.

    httpx кладет полный адрес запроса в текст ошибки, а у Telegram токен стоит
    прямо в пути. Такой текст уезжал бы в ответ на "проверить", в журнал и в
    вывод `docker logs`, поэтому сообщение собираем сами и на всякий случай
    затираем известные секреты.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "").strip()[:200]
        message = f"HTTP {exc.response.status_code}" + (f": {body}" if body else "")
    else:
        message = f"{type(exc).__name__}: {exc}"
    return _redact(message, *secrets)


def _telegram_html(text: str, link: str) -> str:
    """В Telegram слово "Sekvyr" становится ссылкой на панель."""
    safe = html.escape(text)
    anchor = f'<a href="{html.escape(link, quote=True)}">Sekvyr</a>'
    return safe.replace("Sekvyr", anchor, 1)


async def send(cfg: dict, text: str, link: str = "") -> list[str]:
    """Шлет текст во все настроенные каналы. Возвращает список ошибок."""
    global last_delivery
    errors: list[str] = []
    token, chat = cfg.get("telegram_token"), cfg.get("telegram_chat")
    if token and chat:
        base = (cfg.get("telegram_api") or "https://api.telegram.org").rstrip("/")
        url = f"{base}/bot{token}/sendMessage"
        payload: dict = {"chat_id": chat, "disable_web_page_preview": True}
        if link:
            payload["text"] = _telegram_html(text, link)
            payload["parse_mode"] = "HTML"
        else:
            payload["text"] = text
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                response = await http.post(url, json=payload)
                response.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - оповещение не роняет дело
            message = _error_text(exc, token, url, base)
            errors.append(f"Telegram: {message}")
            log.warning("оповещение в Telegram не ушло: %s", message)

    if cfg.get("webhook"):
        try:
            body: dict = {"text": text}
            if link:
                body["link"] = link
            async with httpx.AsyncClient(timeout=10) as http:
                response = await http.post(cfg["webhook"], json=body)
                response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            message = _error_text(exc, cfg["webhook"])
            errors.append(f"Вебхук: {message}")
            log.warning("оповещение в вебхук не ушло: %s", message)
    last_delivery = not errors
    return errors


# Отправки, идущие в фоне: ссылка держится, пока задача не кончится, иначе
# сборщик мусора мог бы снять ее на полпути.
_background: set[asyncio.Task] = set()


async def _send_quietly(cfg: dict, text: str) -> None:
    try:
        await send(cfg, text, get_settings().panel_url)
    except Exception:  # noqa: BLE001
        log.warning("оповещение не отправлено", exc_info=True)


async def notify(session: AsyncSession, text: str) -> None:
    """Разовое оповещение по ходу обработки запроса. Ошибки гасятся.

    Сессия здесь только чтобы прочитать настройки: ничего не пишем и не
    коммитим - вызывающий может быть в середине своей транзакции.

    Сама отправка идет в фоне. Вызывающий держит блокировки окружений и
    журнала, а канал может отвечать по 10 секунд: при лежащем Telegram каждая
    правка прода останавливала все, что пишет журнал, включая чтения агентов.
    """
    try:
        cfg = await get_config(session)
        if not enabled(cfg):
            return
    except Exception:  # noqa: BLE001
        log.warning("оповещение не отправлено", exc_info=True)
        return
    task = asyncio.create_task(_send_quietly(cfg, text))
    _background.add(task)
    task.add_done_callback(_background.discard)


async def notify_later(session_factory, text: str) -> bool:
    """То же, но со своей сессией - для фоновых задач и старта панели.

    Возвращает, дошло ли сообщение хоть в один канал (или каналов нет вовсе:
    тогда и доставлять нечего). Разовые оповещения ставят отметку "сказано"
    только после доставки: иначе тревога, отправленная в лежащий канал, не
    повторялась никогда.
    """
    try:
        async with session_factory() as session:
            cfg = await get_config(session)
        if not enabled(cfg):
            return True
        channels = int(bool(cfg.get("telegram_token") and cfg.get("telegram_chat"))) + int(
            bool(cfg.get("webhook"))
        )
        errors = await send(cfg, text, get_settings().panel_url)
        return len(errors) < channels
    except Exception:  # noqa: BLE001
        log.warning("фоновое оповещение не отправлено", exc_info=True)
        return False
