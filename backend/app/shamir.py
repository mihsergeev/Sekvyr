"""Разделение корневого ключа на доли (схема Шамира над GF(256)).

Зачем: корневой ключ не должен целиком лежать ни у одного человека и ни в одном
файле. Панель выдает n долей, для распечатывания нужны любые k из них. Меньше k
долей не дают о ключе ВООБЩЕ ничего - это свойство схемы, а не "трудно
перебрать".

Как устроено: каждый байт ключа - свободный член случайного многочлена степени
k-1 над GF(256); доля с номером x - значения всех этих многочленов в точке x.
Восстановление - интерполяция Лагранжа в нуле.

Про реализацию. Умножение в поле сделано без таблиц логарифмов, побитовым
методом с постоянным числом шагов: табличная версия быстрее, но время обращения
к таблице зависит от данных, а данные здесь - доли корневого ключа. Скорость на
32 байтах никого не волнует.

Формат доли, который видит человек:

    SEKVYR-1-<base64url>   где под base64 лежит
    версия(1) | отпечаток ключа(4) | номер(1) | данные(32) | контроль(4)

Отпечаток - первые байты sha256 корневого ключа: доля от другого сейфа (или от
прошлой инициализации) отвергается сразу, а не после набора порога. Контрольная
сумма ловит опечатку при переносе руками - иначе неверно скопированная доля
выглядит как "не хватает еще одной".
"""

from __future__ import annotations

import base64
import hashlib
import os

PREFIX = "SEKVYR-1-"
_VERSION = 1
_FP_LEN = 4
_CRC_LEN = 4


class ShareError(Exception):
    """Доля не разобралась: испорчена, от другого сейфа или чужого формата."""


# --- арифметика GF(2^8), полином 0x11B (как в AES) -------------------------


def _mul(a: int, b: int) -> int:
    """Умножение в GF(256) за фиксированные 8 шагов, без ветвлений по данным."""
    result = 0
    for _ in range(8):
        # прибавляем a, если младший бит b единица - маской, а не if
        result ^= a & -(b & 1)
        b >>= 1
        high = a & 0x80
        a = (a << 1) & 0xFF
        a ^= 0x1B & -(high >> 7)
    return result


def _inv(a: int) -> int:
    """Обратный элемент: a^254 = a^-1 в GF(256). Через возведение в степень,
    чтобы не заводить таблицу."""
    if a == 0:
        raise ZeroDivisionError("в GF(256) нет обратного к нулю")
    result = 1
    power = a
    for bit in range(8):
        if (254 >> bit) & 1:
            result = _mul(result, power)
        power = _mul(power, power)
    return result


def fingerprint(secret: bytes) -> bytes:
    return hashlib.sha256(secret).digest()[:_FP_LEN]


def _crc(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()[:_CRC_LEN]


def _encode(index: int, data: bytes, fp: bytes) -> str:
    body = bytes([_VERSION]) + fp + bytes([index]) + data
    raw = body + _crc(body)
    return PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode(share: str) -> tuple[bytes, int, bytes]:
    text = share.strip()
    if not text.upper().startswith(PREFIX):
        raise ShareError("это не доля Sekvyr")
    payload = text[len(PREFIX) :]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except Exception as exc:  # noqa: BLE001 - любая проблема разбора одинакова
        raise ShareError("доля испорчена") from exc
    if len(raw) < 1 + _FP_LEN + 1 + 1 + _CRC_LEN:
        raise ShareError("доля испорчена")
    body, crc = raw[:-_CRC_LEN], raw[-_CRC_LEN:]
    if _crc(body) != crc:
        raise ShareError("доля не сходится с контрольной суммой — проверьте, чем копировали")
    if body[0] != _VERSION:
        raise ShareError("доля другого формата")
    fp = body[1 : 1 + _FP_LEN]
    index = body[1 + _FP_LEN]
    data = body[2 + _FP_LEN :]
    if index == 0:
        raise ShareError("доля испорчена")  # x=0 - это сам секрет, такой доли не бывает
    return fp, index, data


def share_index(share: str) -> int:
    """Номер доли. Заодно проверяет формат и контрольную сумму, поэтому годится
    как "разбери и скажи, годная ли" при приеме доли от человека."""
    _, index, _ = _decode(share)
    return index


def split(secret: bytes, *, shares: int, threshold: int) -> list[str]:
    """Разбивает секрет на `shares` долей, из которых достаточно `threshold`."""
    if not 2 <= threshold <= shares <= 255:
        raise ValueError("нужно 2 <= порог <= число долей <= 255")
    fp = fingerprint(secret)
    # коэффициенты многочленов: по одному набору на каждый байт секрета
    out: list[bytes] = [bytearray() for _ in range(shares)]
    for byte in secret:
        coeffs = [byte] + list(os.urandom(threshold - 1))
        for i in range(shares):
            x = i + 1
            y = 0
            for coeff in reversed(coeffs):  # схема Горнера
                y = _mul(y, x) ^ coeff
            out[i].append(y)
    return [_encode(i + 1, bytes(data), fp) for i, data in enumerate(out)]


def combine(shares: list[str]) -> bytes:
    """Восстанавливает секрет из долей. Проверяет, что доли от одного сейфа и не
    повторяются: две копии одной доли - это одна доля, и молча считать их двумя
    значило бы "распечатать" сейф порогом ниже заявленного."""
    if not shares:
        raise ShareError("нет ни одной доли")
    parsed = [_decode(s) for s in shares]
    fps = {fp for fp, _, _ in parsed}
    if len(fps) > 1:
        raise ShareError("доли от разных ключей")
    indexes = [index for _, index, _ in parsed]
    if len(set(indexes)) != len(indexes):
        raise ShareError("одна и та же доля подана дважды")
    lengths = {len(data) for _, _, data in parsed}
    if len(lengths) > 1:
        raise ShareError("доли разной длины")

    size = lengths.pop()
    secret = bytearray()
    for position in range(size):
        total = 0
        for _, xi, data_i in parsed:
            # базисный многочлен Лагранжа в нуле: произведение xj / (xi ^ xj)
            numerator, denominator = 1, 1
            for _, xj, _ in parsed:
                if xj == xi:
                    continue
                numerator = _mul(numerator, xj)
                denominator = _mul(denominator, xi ^ xj)
            total ^= _mul(data_i[position], _mul(numerator, _inv(denominator)))
        secret.append(total)
    return bytes(secret)


def matches(secret: bytes, shares: list[str]) -> bool:
    """Сошелся ли отпечаток восстановленного ключа с тем, что записан в долях.

    Отдельная проверка нужна потому, что интерполяция ВСЕГДА что-то возвращает:
    из неверных долей получится правдоподобный мусор, а не ошибка.
    """
    try:
        fps = {fp for fp, _, _ in (_decode(s) for s in shares)}
    except ShareError:
        return False
    return len(fps) == 1 and fingerprint(secret) == fps.pop()
