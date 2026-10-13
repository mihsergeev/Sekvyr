"""Пароли, токены доступа и хеши.

Здесь только аутентификация людей. Шифрование значений секретов - отдельный
слой (app/crypto.py): у него другие ключи, другой жизненный цикл и другая
модель угроз, и смешивать их в одном модуле не стоит.
"""

import asyncio
import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

# Минимальная длина пароля учетки. Одно место на всю панель: правило работает и
# в схемах API, и в проверке стартового пароля, и в подсказках интерфейса.
# Расхождение с фронтендом ловит ops/selfcheck.py.
MIN_PASSWORD_LEN = 12
# bcrypt учитывает только первые 72 байта, а bcrypt 5 на длинном пароле падает.
# Кириллица - два байта на букву, так что это 36 русских букв.
MAX_PASSWORD_BYTES = 72


class PasswordTooLong(ValueError):
    """Пароль длиннее, чем bcrypt способен учесть: отказ с объяснением, а не 500."""


def hash_password(password: str) -> str:
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        raise PasswordTooLong(
            "Пароль длиннее 72 байт: bcrypt учитывает только первые 72, "
            "а это 36 русских букв. Сократите его"
        )
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


# bcrypt - около 170 мс процессора на попытку. В цикле событий он стоял бы
# поперек всего процесса, и подбор пароля останавливал бы заодно и выдачу
# значений машинам. В своем пуле из двух потоков он идет рядом и не занимает
# под такой подбор все ядра сразу.
_BCRYPT = ThreadPoolExecutor(max_workers=2, thread_name_prefix="bcrypt")


async def verify_password_async(password: str, password_hash: str) -> bool:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_BCRYPT, verify_password, password, password_hash)


async def hash_password_async(password: str) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_BCRYPT, hash_password, password)


def generate_token(nbytes: int = 32) -> str:
    """Случайный токен (~256 бит) для машин и одноразовых ссылок. Показывается
    ровно один раз - в базе остается только его хеш."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 токена: он высокоэнтропийный, медленный bcrypt здесь не нужен;
    в базе - только хеш, поэтому её утечка не дает рабочих токенов."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(
    username: str, secret: str, ttl_minutes: int, token_version: int = 0
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "ver": token_version,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(token: str, secret: str) -> dict | None:
    """Payload при верной подписи и живом сроке, иначе None."""
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if not isinstance(payload.get("sub"), str):
        return None
    return payload
