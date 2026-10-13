"""Корневой ключ и состояние состояния замка.

Панель поднимается **запертой**: база подключена, вход работает, но ни одно
значение не читается - расшифровать их нечем. Корневой ключ живет только в
памяти процесса и появляется там одним из двух способов:

  * **доли (3 из 5).** Люди по очереди подают свои доли; когда набирается порог,
    ключ восстанавливается. Ни у кого нет ключа целиком, и дамп базы вместе с
    образом диска не дает ничего.
  * **переменная окружения.** Ключ лежит рядом с панелью, и она поднимается
    сама после перезагрузки. Проще в эксплуатации, слабее по последствиям:
    root на хосте означает доступ ко всем значениям.

Режим выбирается один раз при инициализации и записан в базе - панель должна
уметь сказать, чего она ждет, а не молчать в состоянии "почему-то 503".

Проверка ключа - маркер: известная строка, зашифрованная корневым ключом при
инициализации. Верный ключ её расшифровывает, неверный - нет. Самого ключа в
базе нет ни в каком виде, даже хеша: хеш от 32 случайных байт не перебирается,
но и не нужен, а лишний материал рядом с секретами - лишний риск.

Одно честное ограничение: ключ живет в памяти ОДНОГО процесса. Пока панель
работает одним контейнером (так и есть в compose), этого достаточно; при
нескольких воркерах отпирать пришлось бы каждый, и общий канал для этого
появится вместе с масштабированием.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto, settings_store, shamir

log = logging.getLogger("sekvyr.sealbox")

VERIFIER_TEXT = b"sekvyr-root-v1"

MODE_SHARES = "shares"
MODE_ENV = "env"

# ключи в app_settings
_MODE = "vault_mode"
_GEN = "vault_root_generation"
_VERIFIER_NONCE = "vault_verifier_nonce"
_VERIFIER_CT = "vault_verifier_ct"
_SHARES = "vault_shares"
_THRESHOLD = "vault_threshold"
_AUTO = "vault_auto_unseal"


class SealedError(Exception):
    """Панель заперта: значения недоступны, пока не введен корневой ключ."""


class NotInitializedError(Exception):
    """Сейф еще не заводили - нет ни корневого ключа, ни маркера проверки."""


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


@dataclass
class VaultMeta:
    mode: str = ""
    generation: int = 0
    shares: int = 0
    threshold: int = 0
    verifier_nonce: str = ""
    verifier_ct: str = ""
    # Намерение, а не факт: собирались ли класть ключ на сервер. Панель сверяет
    # его с настройками и предупреждает заранее - иначе расхождение всплывает
    # ровно в момент перезапуска, когда некому его заметить.
    auto_unseal: bool = False

    @property
    def initialized(self) -> bool:
        return bool(self.verifier_ct)


async def read_meta(session: AsyncSession) -> VaultMeta:
    raw = await settings_store.get_many(session, "vault_")
    return VaultMeta(
        mode=raw.get(_MODE, ""),
        generation=int(raw.get(_GEN, "0") or 0),
        shares=int(raw.get(_SHARES, "0") or 0),
        threshold=int(raw.get(_THRESHOLD, "0") or 0),
        verifier_nonce=raw.get(_VERIFIER_NONCE, ""),
        verifier_ct=raw.get(_VERIFIER_CT, ""),
        auto_unseal=raw.get(_AUTO, "0") == "1",
    )


async def _write_meta(session: AsyncSession, meta: VaultMeta) -> None:
    await settings_store.put(session, _MODE, meta.mode)
    await settings_store.put(session, _GEN, str(meta.generation))
    await settings_store.put(session, _SHARES, str(meta.shares))
    await settings_store.put(session, _THRESHOLD, str(meta.threshold))
    await settings_store.put(session, _VERIFIER_NONCE, meta.verifier_nonce)
    await settings_store.put(session, _VERIFIER_CT, meta.verifier_ct)
    await settings_store.put(session, _AUTO, "1" if meta.auto_unseal else "0")


def _make_verifier(root: bytes, generation: int) -> tuple[str, str]:
    nonce, ct = crypto.encrypt(
        root, VERIFIER_TEXT, crypto.root_verifier_aad(generation=generation)
    )
    return b64(nonce), b64(ct)


def check_root(root: bytes, meta: VaultMeta) -> bool:
    """Тот ли это корневой ключ. Поколение входит в связанные данные, поэтому
    ключ прошлого поколения не пройдет даже при сохранившемся маркере."""
    if not meta.initialized:
        return False
    try:
        plain = crypto.decrypt(
            root,
            unb64(meta.verifier_nonce),
            unb64(meta.verifier_ct),
            crypto.root_verifier_aad(generation=meta.generation),
        )
    except (crypto.DecryptionError, ValueError):
        # ValueError - ключ не той длины: собранный из подложенных долей.
        return False
    return plain == VERIFIER_TEXT


@dataclass
class SealBox:
    """Состояние корневого ключа В ЭТОМ процессе.

    Живет в app.state, а не в глобальной переменной модуля: глобальное состояние
    протекает между тестами и делает "запереть" операцией с неочевидной
    областью действия.
    """

    _root: bytes | None = None
    _pending: dict[int, str] = field(default_factory=dict)

    @property
    def unsealed(self) -> bool:
        return self._root is not None

    @property
    def pending_shares(self) -> int:
        return len(self._pending)

    def root(self) -> bytes:
        if self._root is None:
            raise SealedError("панель заперта")
        return self._root

    def set_root(self, root: bytes) -> None:
        self._root = root
        self._pending.clear()

    def seal(self) -> None:
        """Выбрасывает ключ из памяти. Накопленные доли тоже: иначе "запереть"
        оставляло бы сейф наполовину открытым."""
        self._root = None
        self._pending.clear()

    def add_share(self, share: str) -> None:
        """Кладет долю в набор. Ключ по номеру доли - повторная подача той же
        доли не приближает к порогу."""
        # разбор здесь же ловит порчу и опечатку в доле - до того, как человек
        # решит, что "не хватает еще одной"
        self._pending[shamir.share_index(share)] = share

    def try_combine(self, meta: VaultMeta) -> bytes | None:
        """Пытается собрать ключ, когда долей достаточно. Возвращает ключ только
        если он сошелся с маркером проверки; иначе набор сбрасывается - среди
        поданных долей есть чужая, и продолжать копить бессмысленно."""
        if meta.threshold <= 0 or len(self._pending) < meta.threshold:
            return None
        try:
            candidate = shamir.combine(list(self._pending.values()))
        except (shamir.ShareError, ValueError):
            # Доли от разных ключей (старая доля после смены корня) или разной
            # длины не собираются вовсе. Раньше это было 500 на каждой следующей
            # доле, пока панель не перезапустят: набор не сбрасывался.
            self._pending.clear()
            return None
        if not check_root(candidate, meta):
            self._pending.clear()
            return None
        return candidate


async def initialize(
    session: AsyncSession,
    *,
    mode: str,
    shares: int = 5,
    threshold: int = 3,
    auto_unseal: bool = False,
) -> tuple[bytes, list[str]]:
    """Заводит сейф: генерирует корневой ключ и маркер проверки.

    Возвращает сам ключ и (для режима долей) список долей. Это ЕДИНСТВЕННЫЙ
    момент, когда панель показывает их: ни ключ, ни доли в базу не пишутся, и
    восстановить их потом неоткуда.
    """
    meta = await read_meta(session)
    if meta.initialized:
        raise ValueError("сейф уже заведён")
    if mode not in (MODE_SHARES, MODE_ENV):
        raise ValueError("неизвестный режим корневого ключа")

    root = crypto.new_key()
    generation = 1
    nonce, ct = _make_verifier(root, generation)
    parts = (
        shamir.split(root, shares=shares, threshold=threshold)
        if mode == MODE_SHARES
        else []
    )
    await _write_meta(
        session,
        VaultMeta(
            mode=mode,
            generation=generation,
            shares=shares if mode == MODE_SHARES else 0,
            threshold=threshold if mode == MODE_SHARES else 0,
            verifier_nonce=nonce,
            verifier_ct=ct,
            auto_unseal=auto_unseal and mode == MODE_ENV,
        ),
    )
    return root, parts


async def rewrap_root(session: AsyncSession, new_root: bytes, generation: int) -> None:
    """Обновляет маркер под новый корневой ключ (при ротации). Обертки ключей
    окружений перекладывает вызывающий - здесь только маркер и поколение."""
    meta = await read_meta(session)
    nonce, ct = _make_verifier(new_root, generation)
    meta.generation = generation
    meta.verifier_nonce = nonce
    meta.verifier_ct = ct
    await _write_meta(session, meta)


def root_from_env(root_key: str, root_key_file: str) -> bytes | None:
    """Корневой ключ для автоотпирания: из переменной или из файла.

    Файл предпочтительнее переменной: содержимое переменных видно в `docker
    inspect` и в окружении процесса, а файл можно положить с правами 0400 и
    отдельным владельцем. Поддерживаем оба, потому что в оркестраторах бывает
    удобно ровно одно из двух.
    """
    raw = ""
    if root_key_file:
        path = Path(root_key_file)
        if not path.exists():
            # Не ошибка: файла нет, пока владелец не включил автоматическое
            # отпирание. Панель просто поднимется запертой и попросит ключ.
            log.info("Файла ключа пока нет (%s) — панель поднимется запертой", path)
            return None
        raw = path.read_text(encoding="utf-8").strip()
    elif root_key:
        raw = root_key.strip()
    if not raw:
        return None
    try:
        key = unb64(raw)
    except Exception:  # noqa: BLE001 - мусор в переменной = ключа нет
        log.error("корневой ключ не разобрался как base64 — панель останется запертой")
        return None
    if len(key) != crypto.KEY_SIZE:
        log.error(
            "корневой ключ не той длины (%d байт вместо %d) — панель останется запертой",
            len(key),
            crypto.KEY_SIZE,
        )
        return None
    return key
