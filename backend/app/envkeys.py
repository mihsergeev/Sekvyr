"""Ключи окружений: свой ключ у каждого окружения, обернутый корневым.

Зачем отдельный уровень, а не шифрование всего сразу корневым ключом:

  * ротация корневого ключа перекладывает несколько десятков оберток, а не
    миллион значений;
  * значения одного окружения расшифровываются своим ключом, поэтому "утек
    ключ dev" не означает "утек prod";
  * есть место для ключа, которого сервер не знает вовсе: ключ проекта с
    шифрованием в браузере (docs/e2e.md).

Открытый ключ окружения нигде не хранится и не кешируется: он разворачивается
из обертки на каждое обращение. Это одно AES-GCM на 32 байтах - дешевле, чем
думать о том, когда чистить кеш при запирании.
"""

from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.models import EnvKey
from app.sealbox import SealBox, b64, read_meta, unb64


class MissingKeyError(Exception):
    """У окружения нет ключа нужного поколения. Значит либо база испорчена, либо
    ротация оборвалась на середине - молча создавать новый ключ здесь нельзя:
    старые значения после этого не расшифруются никогда."""


# Номер общей блокировки ключевого материала (в Postgres - advisory lock).
MATERIAL_LOCK = 0x53454B56


async def lock_material(session: AsyncSession, *, exclusive: bool = False) -> None:
    """Смена корневого ключа и новые ключи окружений не идут одновременно.

    Смена корневого переобертывает все ключи окружений одной транзакцией. Ключ,
    заведенный в это время другой транзакцией (новое окружение, смена ключа
    окружения), остался бы обернут прежним корневым, который после коммита
    смены уже никто не знает, и значения окружения перестали бы читаться.
    Поэтому новые ключи берут общую блокировку, а смена корневого -
    исключительную. В SQLite (тесты) транзакции и так идут по одной.
    """
    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    fn = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
    await session.execute(text(f"SELECT {fn}(:key)"), {"key": MATERIAL_LOCK})


async def create(session: AsyncSession, box: SealBox, env_id: int, *, generation: int = 1,
                 root_generation: int | None = None) -> tuple[int, bytes]:
    """Заводит ключ окружения и кладет в базу его обертку.

    Поколение корневого ключа по умолчанию - текущее: окружение, заведенное
    после смены корневого ключа, раньше записывалось с поколением 1.
    """
    await lock_material(session)
    if root_generation is None:
        root_generation = (await read_meta(session)).generation or 1
    key = crypto.new_key()
    nonce, wrapped = crypto.encrypt(
        box.root(), key, crypto.env_key_aad(env_id=env_id, generation=generation)
    )
    session.add(
        EnvKey(
            environment_id=env_id,
            generation=generation,
            root_generation=root_generation,
            nonce=b64(nonce),
            wrapped_key=b64(wrapped),
            active=True,
        )
    )
    return generation, key


async def _unwrap(box: SealBox, row: EnvKey) -> bytes:
    return crypto.decrypt(
        box.root(),
        unb64(row.nonce),
        unb64(row.wrapped_key),
        crypto.env_key_aad(env_id=row.environment_id, generation=row.generation),
    )


async def active(session: AsyncSession, box: SealBox, env_id: int) -> tuple[int, bytes]:
    """Текущий ключ окружения: им шифруются новые значения."""
    row = await session.scalar(
        select(EnvKey).where(EnvKey.environment_id == env_id, EnvKey.active.is_(True))
    )
    if row is None:
        raise MissingKeyError(f"у окружения {env_id} нет активного ключа")
    return row.generation, await _unwrap(box, row)


async def of_generation(
    session: AsyncSession, box: SealBox, env_id: int, generation: int
) -> bytes:
    """Ключ конкретного поколения - им расшифровываются старые версии, которые
    еще не переехали на новый ключ."""
    row = await session.scalar(
        select(EnvKey).where(
            EnvKey.environment_id == env_id, EnvKey.generation == generation
        )
    )
    if row is None:
        raise MissingKeyError(
            f"у окружения {env_id} нет ключа поколения {generation}"
        )
    return await _unwrap(box, row)


async def rewrap_for_new_root(
    session: AsyncSession, old_root: bytes, new_root: bytes, new_root_generation: int
) -> int:
    """Перекладывает ВСЕ обертки под новый корневой ключ. Возвращает их число.

    Порядок важен: сначала переворачиваем обертки, и только потом меняем маркер
    корневого ключа (см. api/vault.py). Если оборвется посередине - панель
    останется на старом корневом ключе, а часть оберток будет новой; поэтому все
    идет одной транзакцией, и половинчатого состояния не бывает.
    """
    await lock_material(session, exclusive=True)
    rows = list(await session.scalars(select(EnvKey)))
    for row in rows:
        aad = crypto.env_key_aad(env_id=row.environment_id, generation=row.generation)
        key = crypto.decrypt(old_root, unb64(row.nonce), unb64(row.wrapped_key), aad)
        nonce, wrapped = crypto.encrypt(new_root, key, aad)
        row.nonce = b64(nonce)
        row.wrapped_key = b64(wrapped)
        row.root_generation = new_root_generation
    return len(rows)
