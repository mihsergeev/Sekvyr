"""Запечатанный файл: один формат для бэкапа и аварийного архива.

Зачем вообще формат, а не "зашифруй чем-нибудь". Дамп базы содержит хеши
паролей, ключи машин и обертки ключей окружений, а аварийный архив - сами
значения открытым текстом. Оба файла уезжают туда, где панель их уже не
охраняет: на офсайт, на флешку, в сейф. Значит шифровать их надо так, чтобы
расшифровка не требовала ни панели, ни интернета, ни `openssl` нужной версии -
только пароль и `ops/breakglass.py`.

Устройство:

    SEKVYR-SEALED-1 {json-заголовок}\\n
    [4 байта длины][шифротекст]  ... и так по кускам до конца

Куски по мегабайту, а не целиком: файл в несколько гигабайт не должен требовать
столько же памяти ни при записи, ни при чтении.

Что защищает от чего:

  * **Пароль -> ключ через scrypt.** Пароль человек придумывает сам, и он всегда
    слабее 32 случайных байт. scrypt с n=2^15 делает перебор дорогим по памяти,
    а не только по времени: видеокарта здесь не помогает так, как с PBKDF2.
  * **Свой nonce у каждого куска.** Счетчик, а не случайность: повтор пары
    ключ+nonce в GCM ломает сам ключ, а счетчик повториться не может.
  * **Номер куска и признак последнего - в связанных данных.** Куски нельзя
    переставить местами, продублировать или отрезать хвост: расшифровка кусков
    не сойдется, а обрезанный файл кончится без пометки "последний" и будет
    отвергнут. Без этого "бэкап" можно было бы незаметно укоротить.
  * **Заголовок тоже в связанных данных.** Подменить соль или пометку, оставив
    содержимое, не выйдет.

Формат читает `ops/breakglass.py` - самостоятельный файл без импортов из
`app/`, чтобы в аварии хватило его одного. Совпадение констант проверяется
тестом и `ops/selfcheck.py`: разъехавшийся формат обнаружится сейчас, а не
тогда, когда понадобится вскрыть архив.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = "SEKVYR-SEALED-1"
CHUNK = 1 << 20  # мегабайт открытого текста на кусок
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_SIZE = 32
NONCE_PREFIX = 8  # байт случайного префикса; еще 4 байта - счетчик кусков
LENGTH = 4  # байт длины куска


class SealedError(Exception):
    """Файл не открылся: не тот пароль, испорчен, обрезан или не наш формат."""


def derive(password: str, salt: bytes, *, n: int = SCRYPT_N, r: int = SCRYPT_R,
           p: int = SCRYPT_P) -> bytes:
    return Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p).derive(password.encode())


def _aad(header_hash: bytes, index: int, final: bool) -> bytes:
    return header_hash + struct.pack(">IB", index, 1 if final else 0)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + struct.pack(">I", index)


def seal(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    password: str = "",
    key: bytes = b"",
    note: str = "",
    kind: str = "",
) -> dict:
    """Запечатывает поток. Пароль ИЛИ готовый ключ на 32 байта - что-то одно.

    Возвращает заголовок: вызывающему обычно нужно записать в журнал, что за
    файл он только что создал.
    """
    if bool(password) == bool(key):
        raise ValueError("нужен либо пароль, либо ключ на 32 байта")
    salt = os.urandom(16)
    if password:
        secret = derive(password, salt)
    else:
        if len(key) != KEY_SIZE:
            raise ValueError("ключ должен быть длиной 32 байта")
        secret = key

    prefix = os.urandom(NONCE_PREFIX)
    head = {
        "v": 1,
        "kdf": "scrypt" if password else "raw",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": salt.hex(),
        "nonce_prefix": prefix.hex(),
        "chunk": CHUNK,
        "kind": kind,
        "note": note,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    line = (MAGIC + " " + json.dumps(head, ensure_ascii=False, sort_keys=True) + "\n").encode()
    dst.write(line)
    head_hash = hashlib.sha256(line).digest()

    aes = AESGCM(secret)
    index = 0
    pending = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        final = not nxt
        blob = aes.encrypt(_nonce(prefix, index), pending, _aad(head_hash, index, final))
        dst.write(struct.pack(">I", len(blob)) + blob)
        if final:
            break
        pending, index = nxt, index + 1
    return head


def read_header(src: BinaryIO) -> dict:
    """Читает заголовок и оставляет поток на первом куске."""
    line = src.readline()
    if not line.startswith(MAGIC.encode()):
        raise SealedError("это не запечатанный файл Sekvyr")
    try:
        head = json.loads(line[len(MAGIC) :].decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise SealedError("заголовок не разобрался") from exc
    head["_hash"] = hashlib.sha256(line).digest()
    return head


def unseal(src: BinaryIO, dst: BinaryIO, *, password: str = "", key: bytes = b"") -> dict:
    """Распечатывает поток. Возвращает заголовок файла.

    Обрыв на середине - ошибка, а не "сколько прочиталось". Молча отдать половину
    бэкапа хуже, чем не отдать ничего: половину заметят через месяц.
    """
    head = read_header(src)
    if head.get("v") != 1:
        raise SealedError("файл новее этой утилиты")
    if head.get("kdf") == "scrypt":
        if not password:
            raise SealedError("файл запечатан паролем — его и нужно ввести")
        secret = derive(
            password,
            bytes.fromhex(head["salt"]),
            n=int(head["n"]),
            r=int(head["r"]),
            p=int(head["p"]),
        )
    else:
        if len(key) != KEY_SIZE:
            raise SealedError("файл запечатан ключом — нужен ключ на 32 байта")
        secret = key

    aes = AESGCM(secret)
    prefix = bytes.fromhex(head["nonce_prefix"])
    head_hash = head["_hash"]
    index = 0
    while True:
        raw = src.read(LENGTH)
        if len(raw) < LENGTH:
            raise SealedError("файл обрывается: последний кусок не помечен как последний")
        size = struct.unpack(">I", raw)[0]
        blob = src.read(size)
        if len(blob) != size:
            raise SealedError("файл обрывается посреди куска")
        nonce = _nonce(prefix, index)
        # Признака "последний" в самом файле нет: он в связанных данных, и мы
        # пробуем оба варианта. Так обрезанный файл не выдать за целый - у
        # предпоследнего куска метка другая, и подделать её без ключа нельзя.
        plain, final = None, False
        for guess in (False, True):
            try:
                plain = aes.decrypt(nonce, blob, _aad(head_hash, index, guess))
            except InvalidTag:
                continue
            final = guess
            break
        if plain is None:
            raise SealedError(
                "не открывается: неверный пароль либо файл испорчен"
                if index == 0
                else "файл испорчен: кусок не сошёлся"
            )
        dst.write(plain)
        if final:
            break
        index += 1
    return head
