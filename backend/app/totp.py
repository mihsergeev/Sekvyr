"""Второй фактор: одноразовые коды по времени (RFC 6238).

Реализация своя и короткая: алгоритм - это HMAC-SHA1 от номера тридцатисекундного
окна, а тянуть зависимость ради двадцати строк в проекте, который хранит чужие
секреты, не хочется. Чем меньше стороннего кода рядом с аутентификацией, тем
меньше поводов однажды обновлять его в спешке.

SHA-1 здесь не выбор, а совместимость: все приложения-аутентификаторы работают
именно так, а стойкость схемы держится не на хеше, а на том, что секрет не
покидает панель и телефон.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

STEP = 30  # длина окна, секунд
DIGITS = 6
# Допуск на расхождение часов: одно окно назад и одно вперед. Больше - значит
# дольше живет подсмотренный код, меньше - люди не успевают ввести.
WINDOW = 1


def new_secret() -> str:
    """Секрет в base32 без выравнивания - в таком виде его принимают приложения."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _code(secret: str, counter: int) -> str:
    padding = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret.upper() + padding)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10**DIGITS)).zfill(DIGITS)


def counter_now(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def verify(secret: str, code: str, *, last_counter: int = 0, now: float | None = None) -> int | None:
    """Проверяет код и возвращает номер окна, в котором он сошелся.

    `last_counter` - номер окна, в котором код принимали в прошлый раз. Все, что
    не больше него, отвергается: иначе подсмотренный код работает еще полминуты,
    и "одноразовый" он только по названию.

    Сравнение через `compare_digest`: разница во времени ответа при посимвольном
    сравнении подсказывает, сколько цифр угадано.
    """
    code = code.strip().replace(" ", "")
    # isascii обязателен: isdigit пропускает и арабские, и надстрочные цифры, а
    # compare_digest на них падает, и вместо отказа выходил 500 мимо лимитера.
    if not (code.isascii() and code.isdigit()) or len(code) != DIGITS:
        return None
    current = counter_now(now)
    for shift in range(-WINDOW, WINDOW + 1):
        counter = current + shift
        if counter <= last_counter:
            continue
        if hmac.compare_digest(_code(secret, counter), code):
            return counter
    return None


def provisioning_uri(secret: str, username: str, issuer: str = "Sekvyr") -> str:
    """Ссылка otpauth:// - её показывают QR-кодом или дают скопировать руками."""
    # Двоеточие в метке НЕ кодируем: это разделитель "издатель:пользователь",
    # и приложения-аутентификаторы показывают %3A как есть, отчего в списке
    # появляется "Sekvyr%3Aivan".
    label = quote(f"{issuer}:{username}", safe=":")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP}"
    )
