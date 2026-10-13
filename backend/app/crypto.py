"""Примитивы шифрования.

Один алгоритм на всю панель - AES-256-GCM из `cryptography` (это OpenSSL, а не
самодельщина). Своего кода здесь ровно столько, сколько нужно, чтобы связать
шифротекст с его местом в базе.

**Привязка к месту (AAD).** GCM позволяет подписать данные, которые не
шифруются, но входят в проверку целостности. Мы кладем туда "адрес" значения:
окружение, секрет, имя и номер версии. Из-за этого строку в базе нельзя:

  * скопировать из dev в prod - не совпадет окружение;
  * подставить на место другого ключа - не совпадет имя;
  * откатить на старую версию подменой строки - не совпадет номер.

Во всех случаях расшифровка не просто вернет мусор, а завершится ошибкой:
GCM проверяет тег до того, как отдать открытый текст. Без AAD администратор
базы (или дырка в SQL) молча заменяет прод-пароль на известный ему, и снаружи
это выглядит совершенно нормально.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # 96 бит - рекомендованный для GCM размер
ALG = "AES-256-GCM"


class DecryptionError(Exception):
    """Шифротекст не сошелся: не тот ключ, испорченные данные или значение
    оказалось не на своем месте (не совпал AAD)."""


def new_key() -> bytes:
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, aad: str) -> tuple[bytes, bytes]:
    """Возвращает (nonce, ciphertext). Nonce - свой на КАЖДОЕ шифрование:
    повторное использование пары ключ+nonce в GCM ломает не только эту запись,
    а сам ключ."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad.encode())


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: str) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad.encode())
    except InvalidTag as exc:
        # Наружу отдаем одну и ту же ошибку на все причины: по разнице "не тот
        # ключ" и "не то место" подбирают, что именно подменено.
        raise DecryptionError("шифротекст не сошёлся") from exc


# --- "адреса" для AAD ------------------------------------------------------
# Разделитель \x1f (unit separator): он не встречается в именах и путях, поэтому
# два разных набора полей не склеиваются в одну строку.


def value_aad(*, env_id: int, secret_id: int, name: str, version: int) -> str:
    """Адрес значения секрета. Имя входит сюда намеренно: переименование ключа
    без перешифровки было бы способом подсунуть приложению чужое значение под
    нужным именем. Поэтому переименование - это новая версия (см. secrets.py)."""
    return "\x1f".join(("v1", str(env_id), str(secret_id), name, str(version)))


def env_key_aad(*, env_id: int, generation: int) -> str:
    """Адрес обернутого ключа окружения: обертку нельзя переставить в другое
    окружение или выдать за другое поколение при ротации."""
    return "\x1f".join(("envkey1", str(env_id), str(generation)))


def root_verifier_aad(*, generation: int) -> str:
    return "\x1f".join(("rootcheck1", str(generation)))
