"""Секреты: запись, чтение, удаление, ротация ключа окружения.

Правило, из которого следует все остальное: **значение никогда не
перезаписывается.** Любое изменение - новая версия. Отсюда история, откат и то,
что удаление обратимо: оно тоже версия, просто пустая и помеченная.

Имя и путь хранятся внутри версии и входят в связанные данные шифра, поэтому
переименование - это тоже новая версия с перешифрованным значением. Иначе
переименование было бы способом подсунуть приложению чужое значение под нужным
именем: код читает ключ по имени и получил бы не то, что имелось в виду.

Значения здесь появляются в открытом виде ровно на время вызова. Ни в один
объект, который потом сериализуется наружу, они не кладутся - за этим следит
`ops/selfcheck.py`.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from datetime import datetime, timezone

from sqlalchemy import desc, func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto, e2e, envkeys
from app.models import (
    Environment,
    EnvKey,
    EnvSnapshot,
    EnvSnapshotItem,
    Project,
    Secret,
    SecretVersion,
)
from app.sealbox import SealBox, b64, unb64

STATUS_CURRENT = "current"
STATUS_SUPERSEDED = "superseded"
# Правка от роли ниже порога проекта: версия существует и видна в истории, но
# текущей не становится и на серверы не уезжает, пока её не подтвердят.
STATUS_PENDING = "pending"
STATUS_REJECTED = "rejected"

# Подпись, с которой ожидающая правка снимается, когда ключ изменили иначе:
# предлагали ее к прежнему состоянию, и подтверждение затерло бы новое.
STALE_NOTE = "устарела: ключ изменили позже"


class StaleProposal(Exception):
    """Правку подтверждают, а ключ уже изменили после нее."""


class NotPending(Exception):
    """Правка уже подтверждена, отклонена или снята."""


class SecretNotFound(Exception):
    pass


class SecretChanged(ValueError):
    """Ключ переименовали или перенесли, пока запрос ждал блокировку."""


class SnapshotGone(Exception):
    """Снимок удалили, пока восстановление ждало блокировку."""


class EnvironmentGone(Exception):
    """Окружение удалили (вместе с проектом), пока запрос ждал блокировку."""


def normalize_path(path: str) -> str:
    """Путь всегда вида "/" или "/db/replica": без хвостового слеша, с ведущим.

    Нормализация в одном месте, потому что "/db", "/db/" и "db" - это один и тот
    же каталог для человека, но три разных строки для уникального индекса, и
    тогда в окружении заводятся три ключа с одинаковым именем.
    """
    cleaned = "/" + "/".join(part for part in path.split("/") if part)
    return cleaned


async def get_secret(
    session: AsyncSession, env_id: int, path: str, name: str
) -> Secret | None:
    return await session.scalar(
        select(Secret).where(
            Secret.environment_id == env_id,
            Secret.path == normalize_path(path),
            Secret.name == name,
        )
    )


async def current_version(session: AsyncSession, secret: Secret) -> SecretVersion | None:
    """Версия, которая действует сейчас.

    Ищется по статусу, а не по наибольшему номеру: сверху может лежать правка,
    ожидающая подтверждения, и отдавать её как текущую значило бы, что
    согласование ничего не решает.
    """
    # Старшая, если текущих вдруг две (наследие версий до 1.0.0, см.
    # миграцию 0025): выбор не должен зависеть от порядка строк в базе.
    return await session.scalar(
        select(SecretVersion)
        .where(
            SecretVersion.secret_id == secret.id,
            SecretVersion.status == STATUS_CURRENT,
        )
        .order_by(desc(SecretVersion.version))
        .limit(1)
    )


async def current_versions(
    session: AsyncSession, secret_ids: list[int]
) -> dict[int, SecretVersion]:
    """Текущие версии сразу для многих ключей.

    Кусками по 500: у SQLite есть предел на число параметров запроса, и
    окружение на тысячу ключей упиралось бы в него ровно тогда, когда пачка
    нужнее всего.
    """
    out: dict[int, SecretVersion] = {}
    for start in range(0, len(secret_ids), 500):
        chunk = secret_ids[start : start + 500]
        if not chunk:
            continue
        rows = await session.scalars(
            select(SecretVersion)
            .where(
                SecretVersion.secret_id.in_(chunk),
                SecretVersion.status == STATUS_CURRENT,
            )
            .order_by(SecretVersion.version)
        )
        for version in rows:
            out[version.secret_id] = version  # старшая перекрывает, как в current_version
    return out


async def lock_env(session: AsyncSession, env_id: int) -> None:
    """Один писатель на окружение за раз.

    Номер новой версии, выбор поколения ключа и смена ключа окружения читают и
    пишут одно и то же. Без блокировки запись, совпавшая со сменой ключа,
    оставалась зашифрованной удаленным поколением и больше не читалась
    (проверено на живой панели), две записи одного ключа брали один номер
    версии, а две смены ключа сталкивались. Строка окружения блокируется до
    конца транзакции; SQLite в тестах блокировок строк не знает и пишет по
    одному и так.

    Режим FOR NO KEY UPDATE, а не FOR UPDATE: писателей он выстраивает по
    одному так же, но не мешает вставкам строк со ссылкой на окружение. Такая
    вставка (отметка о чтении машиной) берет на окружении FOR KEY SHARE, и с
    FOR UPDATE чтение агента и смена ключа ждали друг друга через блокировку
    журнала, пока Postgres не отменял одно из них.
    """
    # Окружение, уже взятое этой транзакцией, второй раз не перечитывается:
    # пока блокировка наша, ключи в нем меняем только мы сами. Восстановление
    # снимка и копия окружения брали блокировку на каждый ключ и каждый раз
    # перечитывали все загруженные ключи - на 2800 ключах это было 131 с.
    # Внимание: точку сохранения (begin_nested) с lock_env внутри откатывать
    # нельзя - Postgres снимет ее блокировку строки, а отметка останется. Таких
    # мест сейчас нет; заводя новое, сбрасывайте session.info["held_envs"].
    held = session.info.get("held_envs")
    transaction = session.sync_session.get_transaction()
    if held is not None and transaction is not None and held[0] is transaction and env_id in held[1]:
        return
    found = await session.scalar(
        select(Environment)
        .where(Environment.id == env_id)
        .with_for_update(key_share=True)
        .execution_options(populate_existing=True)
    )
    # Пока запрос ждал, окружение могли удалить вместе с проектом. Писать по
    # нему дальше значило упереться во внешний ключ (500), а смена ключа
    # окружения советовала бы восстанавливать базу из бэкапа, хотя база цела.
    if found is None:
        raise EnvironmentGone()
    # Строки, загруженные до блокировки, могли устареть: пока запрос ждал,
    # другой переименовал, удалил или вернул ключ. SQLAlchemy отдает прежний
    # объект с прежними полями, и запись по нему расходилась с базой: версия
    # под одним именем, строка под другим, и окружение переставало отдаваться
    # целиком, а "не удален" поверх удаленного в базе не давало UPDATE вовсе.
    # Поэтому все ключи этого окружения, что уже есть в сессии, перечитываются.
    loaded = [
        obj.id
        for obj in list(session.identity_map.values())
        if isinstance(obj, Secret) and inspect(obj).dict.get("environment_id") == env_id
    ]
    if loaded:
        await session.execute(
            select(Secret).where(Secret.id.in_(loaded)).execution_options(populate_existing=True)
        )
    transaction = session.sync_session.get_transaction()
    held = session.info.get("held_envs")
    if held is None or held[0] is not transaction:
        held = (transaction, set())
        session.info["held_envs"] = held
    held[1].add(env_id)


async def lock_secret(session: AsyncSession, secret: Secret) -> None:
    """Блокировка окружения ключа и его свежая строка.

    Маршрут проверяет права по месту ключа до блокировки. Если ключ за это
    время переехал, писать по новому месту нельзя: права на него никто не
    проверял. Удаление места не меняет, и откат удаленного ключа - обычный
    возврат.
    """
    place = (secret.path, secret.name)
    await lock_env(session, secret.environment_id)
    if (secret.path, secret.name) != place:
        raise SecretChanged(
            "ключ переименовали или перенесли, пока выполнялся запрос: обновите страницу"
        )


async def _plain(session: AsyncSession, box: SealBox, secret: Secret, version: SecretVersion) -> str:
    """Открытый текст версии.

    Смена ключа окружения перешифровывает версии и удаляет прежнее поколение
    одной транзакцией. Чтение, которое взяло версию до ее коммита, а ключ после,
    ключа уже не находит: тогда версия перечитывается, и она уже под новым
    ключом.
    """
    try:
        key = await envkeys.of_generation(
            session, box, secret.environment_id, version.env_key_generation
        )
    except envkeys.MissingKeyError:
        await session.refresh(version)
        key = await envkeys.of_generation(
            session, box, secret.environment_id, version.env_key_generation
        )
    return crypto.decrypt(
        key,
        unb64(version.nonce),
        unb64(version.ciphertext),
        crypto.value_aad(
            env_id=secret.environment_id,
            secret_id=secret.id,
            name=version.name_at,
            version=version.version,
        ),
    ).decode()


def _check_place(secret: Secret, version: SecretVersion) -> None:
    """Имя и папка действующей версии совпадают с ключом.

    Имя версии входит в связанные данные шифра, а у ключа - нет. Без этой
    сверки правка строк secrets в базе (поменять местами имена двух ключей,
    перенести ключ в другую папку) отдавала бы чужое значение под нужным именем
    и расшифровывалась бы без ошибки. Сохранение, переименование, подтверждение
    и снимки всегда пишут их одинаковыми, так что расхождение - только правка
    мимо панели.
    """
    if version.name_at != secret.name or version.path_at != secret.path:
        raise crypto.DecryptionError("имя или папка ключа не совпадают с версией")


async def _checked(session: AsyncSession, secret: Secret, version: SecretVersion) -> SecretVersion:
    """Действующая версия, сверенная с ключом (_check_place).

    Строку ключа и версию читают разные запросы, и переименование между ними
    дает честное расхождение: строка еще старая, версия уже новая. Агент на
    этом получал 500 "правка базы" на все окружение. Перед тем как считать это
    правкой, обе строки перечитываются и сверяются еще раз.
    """
    if version.name_at == secret.name and version.path_at == secret.path:
        return version
    await session.execute(
        select(Secret).where(Secret.id == secret.id).execution_options(populate_existing=True)
    )
    fresh = await session.scalar(
        select(SecretVersion)
        .where(SecretVersion.secret_id == secret.id, SecretVersion.status == STATUS_CURRENT)
        .execution_options(populate_existing=True)
    )
    if fresh is None or fresh.deleted or fresh.inherits:
        raise SecretNotFound("секрет удалён или не имеет версий")
    _check_place(secret, fresh)
    return fresh


async def values_of(
    session: AsyncSession,
    box: SealBox,
    env_id: int,
    memo: dict | None = None,
    only: set[int] | None = None,
) -> dict[tuple[str, str], str]:
    """Все действующие значения окружения, включая унаследованные.

    Одним проходом: версии берутся пачкой, ключи окружений - по одному разу на
    поколение. По ключу за раз это два запроса и две расшифровки на каждое
    значение, и на большом парке ожидание становится заметным.

    Удаленные и неполные версии пропускаются молча: вызывающему нужен снимок
    того, что окружение отдает сейчас, а не разбор его истории.

    memo - общий запас на несколько окружений одного запроса (выгрузка
    проекта, список окружений): строки уровня, ключи окружений и открытые
    значения родителя берутся один раз, а не заново в каждом наследнике.
    """
    memo = {} if memo is None else memo
    rows = await effective_list(session, env_id, memo)
    # only - ключи, которые действительно отдают (папки по правам, одно
    # значение на имя): битый старый ключ в закрытой папке иначе ронял чтение
    # всего окружения, а /lint называл его тому, кому папку читать нельзя.
    if only is not None:
        rows = [(secret, level) for secret, level in rows if secret.id in only]
    versions = await current_versions(session, [secret.id for secret, _ in rows])
    keys: dict[tuple[int, int], bytes] = memo.setdefault("keys", {})
    opened: dict[int, str] = memo.setdefault("plain", {})
    out: dict[tuple[str, str], str] = {}
    for secret, _level in rows:
        version = versions.get(secret.id)
        # Переопределение могли снять между списком и версиями: у такой версии
        # нет шифротекста, как и у удаления.
        if version is None or version.deleted or version.inherits:
            continue
        if version.id in opened:
            out[(secret.path, secret.name)] = opened[version.id]
            continue
        try:
            version = await _checked(session, secret, version)
        except SecretNotFound:
            continue
        place = (secret.environment_id, version.env_key_generation)
        key = keys.get(place)
        if key is None:
            try:
                key = await envkeys.of_generation(session, box, *place)
            except envkeys.MissingKeyError:
                # Смена ключа закоммитилась посреди прохода: см. _plain.
                out[(secret.path, secret.name)] = await _plain(session, box, secret, version)
                continue
            keys[place] = key
        plain = crypto.decrypt(
            key,
            unb64(version.nonce),
            unb64(version.ciphertext),
            crypto.value_aad(
                env_id=secret.environment_id,
                secret_id=secret.id,
                name=version.name_at,
                version=version.version,
            ),
        ).decode()
        opened[version.id] = plain
        out[(secret.path, secret.name)] = plain
    return out


async def read_value(session: AsyncSession, box: SealBox, secret: Secret) -> str:
    """Открытое значение текущей версии.

    Расшифровка идет ключом ТОГО поколения, которым значение было зашифровано, и
    с адресом из самой версии: имя, путь и номер берутся из нее, а не из текущего
    состояния секрета. Так после переименования читается ровно то, что записано.
    """
    version = await current_version(session, secret)
    # "Взять у родителя" - тоже отсутствие своего значения: шифротекста у такой
    # версии нет, и расшифровка падала бы на пустом nonce.
    if version is None or version.deleted or version.inherits:
        raise SecretNotFound("секрет удалён или не имеет версий")
    version = await _checked(session, secret, version)
    return await _plain(session, box, secret, version)


async def read_if_alive(session: AsyncSession, box: SealBox, secret: Secret) -> str | None:
    """Значение ключа из пачки или None, если ключ удалили, пока пачка читалась.

    Список ключей и значения читаются разными запросами: удаление, закоммиченное
    между ними, давало 404 на все окружение, и агент оставался без значений из-за
    правки одного ключа. Исчезнувшего ключа в пачке просто нет, как если бы
    список взяли мгновением позже.
    """
    try:
        return await read_value(session, box, secret)
    except SecretNotFound:
        return None


async def _add_version(
    session: AsyncSession,
    box: SealBox,
    secret: Secret,
    *,
    value: str | None,
    name: str,
    path: str,
    deleted: bool,
    author: str,
    comment: str,
    pending: bool = False,
    inherits: bool = False,
) -> SecretVersion:
    await lock_env(session, secret.environment_id)
    # Вторая линия: откат, восстановление снимка и подтверждение пишут мимо
    # write_secret. Сейчас открытого текста в e2e-проекте взяться неоткуда
    # (включить режим можно только в проекте без истории), но любая будущая
    # дорога в обход проверки должна упираться в нее здесь. Проверка - под
    # блокировкой: см. is_e2e.
    if value is not None and not deleted and not inherits and await is_e2e(
        session, secret.environment_id
    ):
        try:
            e2e.check_value(value)
        except e2e.FormatError as exc:
            raise SealedValueRequired(str(exc)) from exc
    generation, key = await envkeys.active(session, box, secret.environment_id)
    # Номер следующий по порядку в любом случае: ожидающая версия - такая же
    # запись истории, просто еще не действующая. Нумеровать её отдельно значило
    # бы завести вторую систему счета, которую пришлось бы объяснять.
    last = await session.scalar(
        select(func.max(SecretVersion.version)).where(SecretVersion.secret_id == secret.id)
    )
    version_no = (last or 0) + 1

    nonce_b64 = ciphertext_b64 = ""
    if not deleted and not inherits:
        nonce, ciphertext = crypto.encrypt(
            key,
            (value or "").encode(),
            crypto.value_aad(
                env_id=secret.environment_id,
                secret_id=secret.id,
                name=name,
                version=version_no,
            ),
        )
        nonce_b64, ciphertext_b64 = b64(nonce), b64(ciphertext)

    # Прежняя текущая версия становится историей - но только если новая
    # действительно вступает в силу. Ожидающая подтверждения ничего не смещает:
    # до подтверждения приложения должны получать прежнее значение.
    if not pending:
        previous = await session.scalar(
            select(SecretVersion).where(
                SecretVersion.secret_id == secret.id,
                SecretVersion.status == STATUS_CURRENT,
            )
        )
        if previous is not None:
            previous.status = STATUS_SUPERSEDED
        await _retire_pending(session, secret, author)

    version = SecretVersion(
        secret_id=secret.id,
        version=version_no,
        name_at=name,
        path_at=path,
        deleted=deleted,
        inherits=inherits,
        nonce=nonce_b64,
        ciphertext=ciphertext_b64,
        env_key_generation=generation,
        status=STATUS_PENDING if pending else STATUS_CURRENT,
        author=author,
        comment=comment,
        multiline="\n" in (value or ""),
    )
    session.add(version)
    if not pending:
        secret.current_version = version_no
        # "наследуется" для списка ключей окружения - то же, что "своего значения
        # здесь нет": ключ показывается как унаследованный, а не как местный.
        secret.deleted = deleted or inherits
        secret.name = name
        secret.path = path
    return version


async def _retire_pending(
    session: AsyncSession, secret: Secret, reviewer: str, below: int | None = None
) -> None:
    """Ожидающие правки ключа, которые устарели: ключ изменили иначе.

    Их предлагали к прежнему значению, имени или папке. Подтвержденная позже,
    такая правка молча затерла бы свежий хотфикс, вернула бы удаленный ключ
    или откатила бы переименование.
    """
    query = select(SecretVersion).where(
        SecretVersion.secret_id == secret.id, SecretVersion.status == STATUS_PENDING
    )
    if below is not None:
        query = query.where(SecretVersion.version < below)
    for stale in await session.scalars(query):
        stale.status = STATUS_REJECTED
        stale.reviewed_by = reviewer
        stale.reviewed_at = datetime.now(timezone.utc)
        stale.review_note = STALE_NOTE


class SealedValueRequired(Exception):
    """В проект с шифрованием в браузере попытались положить открытый текст."""


class BadName(ValueError):
    """Имя ключа, которое сломает файл окружения на сервере."""


# Пробельные и управляющие символы и знак =. Точки, дефисы и кириллицу
# пропускаем: docker compose их принимает, а в таких именах живут, например,
# настройки Spring (spring.datasource.url).
# Кроме того, что ломает файл, - невидимое: управляющие C1, переворот строки
# (U+202E) и символы нулевой ширины. В файле они живут, но в интерфейсе и в
# журнале имя с ними выглядит как другое, а агент C1 все равно пропускает.
_BAD_NAME = re.compile(
    r"[\s=\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)


# Что docker compose принимает в имени переменной: буквы (и кириллицу), цифры,
# _, точку и дефис. На любом другом символе (/, @, $, кавычки, скобки) он не
# разбирает env_file целиком, и не поднимается приложение, а двоеточие считает
# разделителем и молча режет имя: из a:b выходит a со значением "b=...".
_NAME_OK = re.compile(r"[\w.\-]+")


# Метка папки в выгрузке - "# /путь" до конца строки без пробелов. Папку с
# пробелом или # она прочитать не может: при обратной заливке ключ уезжал в
# соседнюю папку и перезаписывал чужой. Поэтому таких папок не заводим.
_BAD_PATH = re.compile(r"[\s#\x00-\x1f\x7f]")


def one_per_name(secrets: list[Secret]) -> list[Secret]:
    """Одно значение на имя - то, что получает сервер.

    Одноименные ключи в разных папках - обычное дело (у каждой службы своя
    папка со своим DB_URL, и каждому серверу выдана только его папка). Но если
    машине выданы обе, в файле окружения папок нет: compose брал последнюю
    строку, а sekvyr run и ESO - первую, и разные потребители получали разные
    значения. Решаем на сервере и одинаково для всех: побеждает папка, которая
    идет позже по порядку путей (/db после /), как в выгрузке целиком.
    """
    last: dict[str, Secret] = {}
    for secret in secrets:
        last[secret.name] = secret
    keep = {id(secret) for secret in last.values()}
    return [secret for secret in secrets if id(secret) in keep]


def check_path(path: str) -> None:
    if _BAD_PATH.search(path):
        raise BadName(
            f'папка "{path[:60]}" не переживет выгрузку и обратную заливку: в пути '
            "не бывает пробелов, # и управляющих символов"
        )


def name_ok(name: str) -> bool:
    try:
        check_name(name)
    except BadName:
        return False
    return True


def check_name(name: str, *, legacy: bool = False) -> None:
    """Отказ для имени, которое сломает .env на сервере.

    Пробел docker compose не принимает вовсе ("key cannot contain a space") и
    не поднимает приложение, знак = отрезал бы имя, перенос строки разорвал бы
    файл, а # в начале сделал бы строку комментарием. Так же он падает на /, @
    и прочем, что не буква, цифра, _, точка или дефис (см. _NAME_OK). Такие
    имена приходили и руками, и импортом, и переносом из Vault, где имя поля
    может быть любым (smtp/host).
    """
    # legacy - имя уже существующего в панели ключа, которое переходит в
    # другое окружение (копия окружения, "взять из соседнего", раскладка).
    # Старое имя (smtp/host до нынешних правил) не должно ронять копию всего
    # окружения: агент и выдача .env такое имя все равно пропустят, а
    # переименовать его можно в любой момент.
    strict_ok = legacy or _NAME_OK.fullmatch(name)
    if not name or _BAD_NAME.search(name) or name.startswith("#") or not strict_ok:
        raise BadName(
            f'имя "{name[:60]}" сломает файл окружения на сервере: в имени ключа '
            "бывают только буквы, цифры, _, точка и дефис"
        )


async def is_e2e(session: AsyncSession, env_id: int) -> bool:
    """Шифрует ли значения этого окружения браузер, а не сервер.

    Из базы, а не из объекта сессии: проект, загруженный в начале запроса,
    помнил бы режим выключенным. Запись спрашивает это под блокировкой
    окружения, а включение режима блокирует все окружения проекта до проверки
    "проект пуст": открытый текст, начатый раньше, виден той проверке, а
    начатый позже дожидается коммита и видит режим.
    """
    query = (
        select(Project.e2e)
        .join(Environment, Environment.project_id == Project.id)
        .where(Environment.id == env_id)
    )
    return bool(await session.scalar(query))


async def set_value(
    session: AsyncSession,
    box: SealBox,
    *,
    env_id: int,
    path: str,
    name: str,
    value: str,
    author: str,
    comment: str = "",
    pending: bool = False,
    legacy_name: bool = False,
) -> SecretVersion:
    """Создает секрет или добавляет ему новую версию. Коммит - на вызывающем.

    В проекте с шифрованием в браузере значение обязано приходить запечатанным.
    Проверка здесь, а не в маршруте: класть в такой проект открытый текст нельзя
    ни импортом, ни переносом, ни откуда-либо еще.
    """
    check_name(name, legacy=legacy_name)
    path = normalize_path(path)
    check_path(path)
    # Блокировка до поиска ключа: иначе две записи нового ключа обе не нашли
    # бы его и обе попытались бы завести.
    await lock_env(session, env_id)
    if await is_e2e(session, env_id):
        try:
            e2e.check_value(value)
        except e2e.FormatError as exc:
            raise SealedValueRequired(str(exc)) from exc
    secret = await get_secret(session, env_id, path, name)
    if secret is None:
        secret = Secret(environment_id=env_id, path=path, name=name, current_version=0)
        session.add(secret)
        # id нужен для адреса шифротекста - получаем его до шифрования
        await session.flush()
    elif secret.deleted and not pending and secret.expires_at is not None:
        # Срок замены был про прежнее значение: напоминать о нем для заново
        # заведенного ключа - ложная тревога.
        secret.expires_at = None
    return await _add_version(
        session,
        box,
        secret,
        value=value,
        name=name,
        path=path,
        deleted=False,
        author=author,
        comment=comment,
        pending=pending,
    )


async def delete_secret(
    session: AsyncSession,
    box: SealBox,
    secret: Secret,
    *,
    author: str,
    comment: str = "",
) -> SecretVersion:
    """Удаление - версия без значения. Ключ пропадает из выдачи, но история
    остается, и вернуть его можно откатом."""
    await lock_secret(session, secret)
    return await _add_version(
        session,
        box,
        secret,
        value=None,
        name=secret.name,
        path=secret.path,
        deleted=True,
        author=author,
        comment=comment,
    )


async def list_secrets(session: AsyncSession, env_id: int) -> list[Secret]:
    """Ключи окружения БЕЗ значений: этим списком пользуются те, кому можно
    знать состав переменных, но не их содержимое."""
    rows = await session.scalars(
        select(Secret)
        .where(Secret.environment_id == env_id, Secret.deleted.is_(False))
        .order_by(Secret.path, Secret.name)
    )
    return list(rows)


async def rotate_env_key(session: AsyncSession, box: SealBox, env_id: int) -> tuple[int, int]:
    """Ротация ключа окружения: новый ключ и перешифровка ВСЕХ версий.

    Возвращает (новое поколение, сколько версий перешифровано).

    Перешифровываем и старые версии тоже, а не только текущие. Иначе пришлось бы
    вечно хранить все прежние поколения ключей - и "ротация" переставала бы
    что-либо значить: скомпрометированный ключ так и оставался бы нужным для
    чтения истории.
    """
    await lock_env(session, env_id)
    old_generation, old_key = await envkeys.active(session, box, env_id)
    new_generation = old_generation + 1

    row = await session.scalar(
        select(EnvKey).where(EnvKey.environment_id == env_id, EnvKey.active.is_(True))
    )
    row.active = False
    _, new_key = await envkeys.create(
        session, box, env_id, generation=new_generation, root_generation=row.root_generation
    )

    secrets = list(
        await session.scalars(select(Secret).where(Secret.environment_id == env_id))
    )
    touched = 0
    # Ключом того поколения, которым версия зашифрована, а не активным: версию
    # под другим поколением (наследие гонки записи со сменой ключа в старых
    # версиях) активный не открывал, и смена ключа падала навсегда.
    keys = {old_generation: old_key}
    for secret in secrets:
        versions = await session.scalars(
            select(SecretVersion).where(SecretVersion.secret_id == secret.id)
        )
        for version in versions:
            if version.deleted or not version.ciphertext:
                version.env_key_generation = new_generation
                continue
            aad = crypto.value_aad(
                env_id=env_id,
                secret_id=secret.id,
                name=version.name_at,
                version=version.version,
            )
            key = keys.get(version.env_key_generation)
            if key is None:
                try:
                    key = await envkeys.of_generation(session, box, env_id, version.env_key_generation)
                except envkeys.MissingKeyError:
                    # Ключа этого поколения нет давно: версию не открыть ни до,
                    # ни после смены. Остается как есть.
                    continue
                keys[version.env_key_generation] = key
            plain = crypto.decrypt(key, unb64(version.nonce), unb64(version.ciphertext), aad)
            nonce, ciphertext = crypto.encrypt(new_key, plain, aad)
            version.nonce = b64(nonce)
            version.ciphertext = b64(ciphertext)
            version.env_key_generation = new_generation
            touched += 1

    # Прежние поколения больше никому не нужны: все, что ими открывалось, переехало.
    for stale in await session.scalars(
        select(EnvKey).where(EnvKey.environment_id == env_id, EnvKey.generation != new_generation)
    ):
        await session.delete(stale)
    return new_generation, touched


# --- история, откат, переименование ---------------------------------------


async def history(session: AsyncSession, secret: Secret) -> list[SecretVersion]:
    """Все версии ключа, новые сверху. Значений здесь нет: список версий может
    смотреть тот, кому нельзя читать сами значения."""
    rows = await session.scalars(
        select(SecretVersion)
        .where(SecretVersion.secret_id == secret.id)
        .order_by(desc(SecretVersion.version))
    )
    return list(rows)


async def read_version(
    session: AsyncSession, box: SealBox, secret: Secret, version_no: int
) -> str:
    """Значение конкретной версии. Расшифровывается ключом ТОГО поколения и с
    адресом из самой версии - имя берется из нее, а не из текущего состояния,
    поэтому после переименования старые версии читаются как записаны."""
    version = await session.scalar(
        select(SecretVersion).where(
            SecretVersion.secret_id == secret.id, SecretVersion.version == version_no
        )
    )
    if version is None or version.deleted or version.inherits:
        raise SecretNotFound("такой версии нет или она была удалением")
    return await _plain(session, box, secret, version)


async def rollback(
    session: AsyncSession,
    box: SealBox,
    secret: Secret,
    version_no: int,
    *,
    author: str,
    pending: bool = False,
) -> SecretVersion:
    """Возврат к прежнему значению.

    Создает НОВУЮ версию с прежним значением, а не воскрешает старую. История
    остается линейной и хранит в том числе то, что откатили: "вернули как было"
    - это тоже изменение, и в журнале оно должно выглядеть изменением.

    Вернуться можно только к версии, которая когда-то действовала. Ожидающая
    или отклоненная правка не действовала ни дня, и откат к ней выпускал бы ее
    в обход подтверждения. Откат роли ниже порога сам ждет подтверждения.
    """
    await lock_secret(session, secret)
    target = await get_version(session, secret, version_no)
    if target is None or target.deleted:
        raise SecretNotFound("такой версии нет или она была удалением")
    if target.status not in (STATUS_CURRENT, STATUS_SUPERSEDED):
        raise ValueError("откатиться можно только к версии, которая действовала")
    if target.inherits:
        raise ValueError("у этой версии нет своего значения: ключ тогда брался у родителя")
    value = await _plain(session, box, secret, target)
    return await _add_version(
        session,
        box,
        secret,
        value=value,
        name=secret.name,
        path=secret.path,
        deleted=False,
        author=author,
        comment=f"откат к версии {version_no}",
        pending=pending,
    )


async def rename(
    session: AsyncSession,
    box: SealBox,
    secret: Secret,
    *,
    new_name: str,
    new_path: str,
    author: str,
) -> SecretVersion:
    """Переименование - новая версия с перешифровкой.

    Имя входит в связанные данные шифра, поэтому иначе и нельзя: правкой строки
    в базе переименование превратилось бы в способ подсунуть приложению чужое
    значение под нужным именем.
    """
    check_name(new_name)
    new_path = normalize_path(new_path)
    check_path(new_path)
    # Все дальше - под блокировкой: значение, прочитанное до нее, затирало
    # запись, закоммиченную, пока переименование ждало, а занятость нового
    # имени проверялась без нее и пропускала ключ, заведенный в это время.
    await lock_secret(session, secret)
    if (new_name, new_path) == (secret.name, secret.path):
        raise ValueError("имя и путь не изменились")
    busy = await get_secret(session, secret.environment_id, new_path, new_name)
    if busy is not None and busy.deleted:
        # Удаленный ключ не виден в списке, но его история живет под этим
        # именем, и слить две истории в одну нельзя. Раньше человек получал
        # "уже есть" про ключ, которого на экране нет.
        raise ValueError(
            "под этим именем здесь хранится история удаленного или взятого у "
            "родителя ключа: верните его из истории или выберите другое имя"
        )
    if busy is not None:
        raise ValueError("ключ с таким именем здесь уже есть")
    value = await read_value(session, box, secret)
    return await _add_version(
        session,
        box,
        secret,
        value=value,
        name=new_name,
        path=new_path,
        deleted=False,
        author=author,
        comment=f"переименован из {secret.path}:{secret.name}",
    )


# --- обмен с .env ----------------------------------------------------------


# Без кавычек пишется только то, что везде читается одинаково.
_BARE = re.compile(r"[A-Za-z0-9_\-.,:/@%+=]+")


def _quote(value: str) -> str:
    """Значение для .env. Файл читают docker compose (env_file) и systemd
    (EnvironmentFile), и значение должно дойти до приложения ровно таким, каким
    его задали.

    Те же правила у агента (agent/main.go, quote) и у ops/breakglass.py, и
    сверены они с настоящим compose:

    - без кавычек - только латиница, цифры и _-.,:/@%+=; "a;rm -rf /" без
      кавычек при source выполнился бы;
    - все прочее - в одинарных кавычках: внутри них compose не подставляет
      переменные и не трогает обратные слеши. В двойных из "P@ss$word1"
      compose подставил бы пустую $word1, и приложение получило бы P@ss;
    - если в значении апостроф, возврат каретки или оно кончается обратным
      слешем, одинарные не годятся (compose примет \\' за экранированную
      кавычку). Тогда двойные с экранированием \\, ", $ и \\r;
    - обратный апостроф не экранируется: compose оставил бы \\` вместе со
      слешем. Shell выполнил бы его, поэтому такой файл не подключают через
      source (docs/app-docker): значение с апострофом и обратным апострофом
      одинаково для compose и shell не записать.

    Многострочное значение пишем переносами как есть, а не одной строкой с
    "\\n": конфиг на двадцать строк, свернутый в одну, нельзя ни прочитать, ни
    поправить в редакторе, а именно за этим файл и выгружают.
    """
    if value == "":
        return '""'
    if _BARE.fullmatch(value):
        return value
    if "'" not in value and "\r" not in value and not value.endswith("\\"):
        return f"'{value}'"
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'


def _close_at(text: str) -> int:
    """Где закрывается двойная кавычка: индекс первой неэкранированной."""
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return i
        i += 1
    return -1


def _unescape(body: str) -> str:
    """Раскрывает экранирование внутри двойных кавычек.

    Посимвольно, а не цепочкой replace: цепочка неизбежно ошибается на
    последовательности "экранированный слэш, затем n" - сначала превращает её в
    перенос строки, а потом уже не отличить одно от другого. Для приватного
    ключа, записанного в одну строку, эта разница как раз и решает.
    """
    # \$ - так экранирует доллар выгрузка: compose читает его как "$".
    codes = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "'": "'", "\\": "\\", "$": "$"}
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            out.append(codes.get(nxt, "\\" + nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


FOLDER_MARK = re.compile(r"^#\s*(/[^\s#]*)\s*$")


def parse_env(text: str, default_path: str = "/") -> list[tuple[str, str, str]]:
    """Разбор .env. Возвращает тройки (папка, имя, значение).

    Понимает `export`, комментарии, обе кавычки и переносы строк внутри двойных
    кавычек. Строка вида `# /infra` переключает папку: ровно так их пишет
    выгрузка, и файл, скачанный отсюда, должен вернуться туда же, откуда взят.
    Остальные комментарии по-прежнему пропускаются.

    Строку, которая не разбирается, молча не пропускаем: вызывающий покажет её
    человеку. Тихо потерянная переменная хуже отказа - её отсутствие заметят уже
    на проде, и не сразу поймут почему.
    """
    out: list[tuple[str, str, str]] = []
    current_path = default_path or "/"
    # BOM в начале оставляют Блокнот и другие редакторы Windows. Не срежь его -
    # и первая переменная получит невидимый символ в имени: в списке она
    # выглядит как DB_URL, а приложение ее не находит.
    # \u0421\u0442\u0440\u043e\u043a\u0438 - \u0442\u043e\u043b\u044c\u043a\u043e \u043f\u043e \n (\u0438 \r\n \u043e\u0442 Windows), \u043d\u0435 splitlines(): \u0442\u043e\u0442 \u0440\u0435\u0436\u0435\u0442 \u0435\u0449\u0435
    # \u043f\u043e \x0b, \x0c, \x85, U+2028 \u0438 U+2029, \u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u0441 \u0442\u0430\u043a\u0438\u043c \u0441\u0438\u043c\u0432\u043e\u043b\u043e\u043c \u0432\u043d\u0443\u0442\u0440\u0438
    # \u043a\u0430\u0432\u044b\u0447\u0435\u043a \u0440\u0430\u0437\u0432\u0430\u043b\u0438\u0432\u0430\u043b\u043e\u0441\u044c \u043d\u0430 \u043a\u0443\u0441\u043a\u0438, \u0430 \u043e\u0431\u043b\u043e\u043c\u043e\u043a \u0432\u0438\u0434\u0430 "x=y" \u0441\u0442\u0430\u043d\u043e\u0432\u0438\u043b\u0441\u044f \u043d\u043e\u0432\u044b\u043c
    # \u043a\u043b\u044e\u0447\u043e\u043c. \u0412\u044b\u0433\u0440\u0443\u0437\u043a\u0430 \u043f\u0438\u0448\u0435\u0442 \u044d\u0442\u0438 \u0441\u0438\u043c\u0432\u043e\u043b\u044b \u043a\u0430\u043a \u0435\u0441\u0442\u044c, \u0438 \u043a\u0440\u0443\u0433 \u0432\u044b\u0433\u0440\u0443\u0437\u043a\u0430 -> \u0438\u043c\u043f\u043e\u0440\u0442
    # \u043e\u0431\u044f\u0437\u0430\u043d \u0438\u0445 \u0441\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c.
    lines = [
        line[:-1] if line.endswith("\r") else line
        for line in text.lstrip("\ufeff").split("\n")
    ]
    index = 0
    while index < len(lines):
        raw = lines[index]
        index += 1
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            mark = FOLDER_MARK.match(line)
            if mark:
                folder = mark.group(1).rstrip("/") or "/"
                current_path = folder[:200]
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise ValueError(f"строка без «=»: {raw.strip()[:60]}")
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if not name:
            raise ValueError(f"пустое имя переменной: {raw.strip()[:60]}")
        check_name(name)
        # Значение в кавычках берем из исходной строки: хвостовые пробелы до
        # переноса внутри кавычек - часть значения.
        quoted = raw.split("=", 1)[1].lstrip()
        if value.startswith('"'):
            # Значение в двойных кавычках может занимать несколько строк -
            # именно так выгружаются конфиги. Собираем до закрывающей кавычки,
            # не трогая отступы: в конфиге они значат ровно то, что видно.
            body = quoted[1:]
            close = _close_at(body)
            while close < 0:
                if index >= len(lines):
                    raise ValueError(f"незакрытая кавычка: {name}")
                body += "\n" + lines[index]
                close = _close_at(body)
                index += 1
            value = _unescape(body[:close])
        elif value.startswith("'"):
            # В одинарных кавычках экранирования нет - как в shell и в docker
            # compose: значение берется буквально до следующей одинарной кавычки
            # и тоже может занимать несколько строк.
            body = quoted[1:]
            close = body.find("'")
            while close < 0:
                if index >= len(lines):
                    raise ValueError(f"незакрытая кавычка: {name}")
                body += "\n" + lines[index]
                close = body.find("'")
                index += 1
            value = body[:close]
        else:
            # без кавычек: хвостовой комментарий отрезаем
            hash_at = value.find(" #")
            if hash_at >= 0:
                value = value[:hash_at].rstrip()
        out.append((current_path, name, value))
    return out


async def env_paths(session: AsyncSession, env_id: int) -> set[str]:
    """Папки ключей, которые окружение отдает (свои и унаследованные)."""
    return {secret.path for secret, _level in await effective_list(session, env_id)}


async def export_env(
    session: AsyncSession,
    box: SealBox,
    env_id: int,
    keep: Callable[[str], bool] | None = None,
    *,
    for_machine: bool = False,
    memo: dict | None = None,
) -> str:
    """Все окружение в формате .env - включая унаследованное.

    В проекте с шифрованием в браузере отказывает: сервер собрал бы файл из
    непрозрачных блобов, и такой "экспорт" был бы хуже отсутствия экспорта.

    Именно включая: файл нужен, чтобы поднять приложение, а приложению все
    равно, где значение задано. Отдельное право и отдельная запись в журнале
    у этой операции потому, что она выносит наружу сразу все.
    """
    if await is_e2e(session, env_id):
        raise SealedValueRequired(
            "у проекта шифрование в браузере: файл собирает тот, у кого есть ключ "
            "проекта, а не сервер"
        )
    lines: list[str] = []
    # Заголовок папки пишем один раз на папку, а не перед каждым ключом: сотня
    # строк "# /infra" подряд - это не структура, а помеха чтению.
    current = "/"
    # Папка, закрытая запретом, в файл не попадает: машина с запретом на
    # /private получала окружение целиком.
    memo = {} if memo is None else memo
    chosen = [
        secret
        for secret, _level in await effective_list(session, env_id, memo)
        if keep is None or keep(secret.path)
    ]
    if for_machine:
        chosen = one_per_name(chosen)
        # Имена, заведенные до нынешних правил (smtp/host из Vault), compose не
        # прочтет и уронит файл целиком: машине их не отдаем, как и агент.
        chosen = [secret for secret in chosen if name_ok(secret.name)]
    plain = await values_of(session, box, env_id, memo, only={secret.id for secret in chosen})
    for secret in chosen:
        value = plain.get((secret.path, secret.name))
        if value is None:
            continue
        if secret.path != current:
            current = secret.path
            if lines:
                lines.append("")
            lines.append(f"# {secret.path}")
        lines.append(f"{secret.name}={_quote(value)}")
    return "\n".join(lines) + ("\n" if lines else "")


async def import_env(
    session: AsyncSession,
    box: SealBox,
    *,
    env_id: int,
    text: str,
    path: str,
    author: str,
    overwrite: bool,
) -> tuple[int, int, list[str]]:
    """Импорт .env. Возвращает (создано, обновлено, пропущено).

    По умолчанию существующие ключи НЕ перезаписываются: импорт чужого файла
    поверх рабочего окружения - самый простой способ незаметно испортить прод,
    и по умолчанию он должен быть безопасным.
    """
    created = updated = 0
    skipped: list[str] = []
    # Проверки "уже есть" - под блокировкой: без нее ключ, заведенный руками,
    # пока импорт ждал, перезаписывался импортом без перезаписи.
    await lock_env(session, env_id)
    for folder, name, value in parse_env(text, path):
        existing = await get_secret(session, env_id, folder, name)
        # Без перезаписи нельзя трогать и значение, которое окружение берет у
        # родителя: свое значение поверх него - такая же замена действующего.
        if not overwrite and await resolve(session, env_id, folder, name) is not None:
            skipped.append(name)
            continue
        was = existing is not None and not existing.deleted
        await set_value(
            session,
            box,
            env_id=env_id,
            path=folder,
            name=name,
            value=value,
            author=author,
            comment="импорт .env",
        )
        if was:
            updated += 1
        else:
            created += 1
    return created, updated, skipped


# --- снимки окружения ------------------------------------------------------


async def snapshot_create(
    session: AsyncSession, *, env_id: int, name: str, author: str
) -> EnvSnapshot:
    """Именованная точка: какой ключ какой версией был сейчас.

    Значения не копируются - они уже лежат в истории. Копировать их второй раз
    значило бы завести еще одно место, откуда шифротекст может утечь, ради
    данных, которые и так никуда не денутся.
    """
    # Снимок - согласованная точка: запись, закоммиченная посреди обхода,
    # иначе попадала бы в него наполовину.
    await lock_env(session, env_id)
    existing = await session.scalar(
        select(EnvSnapshot).where(
            EnvSnapshot.environment_id == env_id, EnvSnapshot.name == name
        )
    )
    if existing is not None:
        raise ValueError("снимок с таким именем уже есть")
    snapshot = EnvSnapshot(environment_id=env_id, name=name, author=author)
    session.add(snapshot)
    await session.flush()
    secrets = await session.scalars(select(Secret).where(Secret.environment_id == env_id))
    for secret in secrets:
        if secret.current_version:
            session.add(
                EnvSnapshotItem(
                    snapshot_id=snapshot.id,
                    secret_id=secret.id,
                    version=secret.current_version,
                )
            )
    return snapshot


async def snapshot_exists(session: AsyncSession, snapshot_id: int) -> bool:
    return (
        await session.scalar(select(EnvSnapshot.id).where(EnvSnapshot.id == snapshot_id))
    ) is not None


def _state(version: SecretVersion | None) -> str:
    """Что ключ окружения отдает сейчас: value, deleted, inherits или none."""
    if version is None:
        return "none"
    if version.deleted:
        return "deleted"
    if version.inherits:
        return "inherits"
    return "value"


async def _snapshot_steps(
    session: AsyncSession, snapshot: EnvSnapshot
) -> list[tuple[Secret, str, SecretVersion | None]]:
    """Что нужно сделать, чтобы окружение стало как в снимке.

    Шаги: delete (поставить удаление), inherit (снова брать у родителя), restore
    (вернуть значение версии). Сравнивается то, что ключ отдает сейчас, а не
    флаг deleted строки: им помечены и удаление, и "взять у родителя", а
    удаление в дочернем окружении еще и прячет значение родителя.
    """
    items = {
        item.secret_id: item.version
        for item in await session.scalars(
            select(EnvSnapshotItem).where(EnvSnapshotItem.snapshot_id == snapshot.id)
        )
    }
    secrets = list(
        await session.scalars(
            select(Secret)
            .where(Secret.environment_id == snapshot.environment_id)
            .order_by(Secret.path, Secret.name)
        )
    )
    current = await current_versions(session, [secret.id for secret in secrets])
    environment = await session.get(Environment, snapshot.environment_id)
    has_parent = environment is not None and environment.parent_id is not None
    # Что родитель отдает сейчас: ключ, которого у родителя нет, после
    # возврата к наследованию просто исчезает, и план должен так и сказать.
    from_parent: set[tuple[str, str]] = set()
    if has_parent:
        from_parent = {
            (s.path, s.name) for s, _level in await effective_list(session, environment.parent_id)
        }
    steps: list[tuple[Secret, str, SecretVersion | None]] = []
    for secret in secrets:
        now = current.get(secret.id)
        state = _state(now)
        wanted = items.get(secret.id)
        if wanted is None:
            # Своей строки у ключа в снимке не было. В окружении с родителем это
            # значит "брали у родителя": свое значение и удаление (которое прячет
            # родительское) возвращаются к наследованию, а не удаляются - иначе
            # "вернуть как было" лишало приложение переменной. Без родителя
            # убирать нужно только действующее значение.
            if has_parent:
                if state in ("value", "deleted"):
                    gone = state == "value" and (secret.path, secret.name) not in from_parent
                    steps.append((secret, "inherit-gone" if gone else "inherit", None))
            elif state == "value":
                steps.append((secret, "delete", None))
            continue
        if now is not None and wanted == now.version:
            continue
        version = await get_version(session, secret, wanted)
        if version is None:
            continue
        target = _state(version)
        if target == "deleted":
            if state != "deleted":
                steps.append((secret, "delete", version))
        elif target == "inherits":
            if state != "inherits":
                # В снимке ключ брался у родителя, а у родителя его больше нет:
                # возврат к наследованию его убирает, и это удаление.
                gone = state == "value" and (secret.path, secret.name) not in from_parent
                steps.append((secret, "inherit-gone" if gone else "inherit", version))
        else:
            steps.append((secret, "restore", version))
    return steps


async def snapshot_plan(
    session: AsyncSession, snapshot: EnvSnapshot
) -> list[tuple[str, str, str]]:
    """Что произойдет при восстановлении: список (путь, имя, действие).

    Предпросмотр нужен из-за одного неочевидного следствия: ключи, заведенные
    ПОСЛЕ снимка, восстановление удаляет - иначе это было бы не "вернуть как
    было", а "долить старое поверх нового". Узнавать об этом лучше до, а не по
    журналу после.
    """
    plan: list[tuple[str, str, str]] = []
    for secret, step, version in await _snapshot_steps(session, snapshot):
        if step == "delete":
            plan.append((secret.path, secret.name, "удалить"))
        elif step == "inherit-gone":
            plan.append((secret.path, secret.name, "убрать: у родителя такого ключа нет"))
        elif step == "inherit":
            plan.append((secret.path, secret.name, "вернуть к наследованию"))
        else:
            plan.append((secret.path, secret.name, f"вернуть версию {version.version}"))
    return plan


async def snapshot_removals(session: AsyncSession, snapshot: EnvSnapshot) -> set[str]:
    """Папки ключей, которые восстановление уберет: на это нужно право удалять."""
    return {
        secret.path
        for secret, step, _version in await _snapshot_steps(session, snapshot)
        if step in ("delete", "inherit-gone")
    }


class RestoreCrossesFolder(Exception):
    """Восстановление перенесло бы старое значение из папки, которую человек
    не читает, под нынешнее имя ключа."""


async def snapshot_restore(
    session: AsyncSession,
    box: SealBox,
    snapshot: EnvSnapshot,
    *,
    author: str,
    can_read: Callable[[str], bool] | None = None,
) -> tuple[int, int]:
    """Восстанавливает окружение к снимку. Возвращает (возвращено, удалено).

    Каждое изменение - новая версия, поэтому неудачное восстановление
    откатывается тем же способом, что и все остальное: снимком "до".
    """
    restored = removed = 0
    note = f"снимок «{snapshot.name}»"
    await lock_env(session, snapshot.environment_id)
    # Снимок без строк читался бы как "в момент снимка ключей не было", и
    # восстановление удаленного параллельно снимка стирало окружение целиком.
    if not await snapshot_exists(session, snapshot.id):
        raise SnapshotGone()
    for secret, step, version in await _snapshot_steps(session, snapshot):
        if step == "delete":
            await delete_secret(session, box, secret, author=author, comment=note)
            removed += 1
            continue
        if step in ("inherit", "inherit-gone"):
            if step == "inherit-gone":
                removed += 1
            else:
                restored += 1
            await _add_version(
                session,
                box,
                secret,
                value=None,
                name=secret.name,
                path=secret.path,
                deleted=False,
                inherits=True,
                author=author,
                comment=note,
            )
            continue
        value = await _plain(session, box, secret, version)
        # Имя и папка - как в снимке, если они свободны. После "переименовал и
        # завел старое имя заново" прежнее имя занято другим ключом, и тогда
        # значение возвращается под нынешним именем, а не роняет восстановление.
        name, path = version.name_at, version.path_at
        busy = await get_secret(session, secret.environment_id, path, name)
        if busy is not None and busy.id != secret.id:
            # Значение уходит из своей папки под нынешнее имя: это чтение той
            # папки. Решается здесь, в момент переноса и под блокировкой: проверка
            # заранее ошибалась и в порядке шагов (предыдущий шаг освобождал
            # место), и в гонке с записью, занявшей место после проверки.
            if version.path_at != secret.path and can_read is not None and not can_read(version.path_at):
                raise RestoreCrossesFolder(version.path_at)
            name, path = secret.name, secret.path
        await _add_version(
            session,
            box,
            secret,
            value=value,
            name=name,
            path=path,
            deleted=False,
            author=author,
            comment=f"{note}, версия {version.version}",
        )
        restored += 1
    return restored, removed


async def snapshot_items_count(session: AsyncSession, snapshot: EnvSnapshot) -> int:
    """Сколько ключей помнит снимок."""
    rows = await session.scalars(
        select(EnvSnapshotItem).where(EnvSnapshotItem.snapshot_id == snapshot.id)
    )
    return len(list(rows))


# --- подтверждение изменений ----------------------------------------------


async def pending_versions(session: AsyncSession, env_id: int) -> list[tuple[Secret, SecretVersion]]:
    """Правки окружения, ожидающие подтверждения."""
    rows = await session.execute(
        select(Secret, SecretVersion)
        .join(SecretVersion, SecretVersion.secret_id == Secret.id)
        .where(
            Secret.environment_id == env_id,
            SecretVersion.status == STATUS_PENDING,
        )
        .order_by(SecretVersion.id)
    )
    return [(secret, version) for secret, version in rows]


async def get_version(
    session: AsyncSession, secret: Secret, version_no: int
) -> SecretVersion | None:
    return await session.scalar(
        select(SecretVersion).where(
            SecretVersion.secret_id == secret.id, SecretVersion.version == version_no
        )
    )


async def approve_version(
    session: AsyncSession, secret: Secret, version: SecretVersion, *, reviewer: str, note: str = ""
) -> None:
    """Подтвержденная правка вступает в силу.

    Ровно в этот момент прежняя текущая версия уходит в историю: до подтверждения
    приложения читали её, и подменять значение раньше было бы неправдой.

    Под блокировкой окружения и с повторной проверкой: правка, после которой
    ключ уже изменили, не применяется (она затерла бы новое), а одновременные
    подтверждение и запись не оставляют ключу двух текущих версий.
    """
    await lock_env(session, secret.environment_id)
    await session.refresh(version)
    if version.status != STATUS_PENDING:
        raise NotPending()
    newer = await session.scalar(
        select(SecretVersion.id).where(
            SecretVersion.secret_id == secret.id,
            SecretVersion.version > version.version,
            SecretVersion.status.in_((STATUS_CURRENT, STATUS_SUPERSEDED)),
        )
    )
    if newer is not None:
        raise StaleProposal()
    await _retire_pending(session, secret, reviewer, below=version.version)
    previous = await session.scalar(
        select(SecretVersion).where(
            SecretVersion.secret_id == secret.id, SecretVersion.status == STATUS_CURRENT
        )
    )
    if previous is not None:
        previous.status = STATUS_SUPERSEDED
    version.status = STATUS_CURRENT
    version.reviewed_by = reviewer
    version.reviewed_at = datetime.now(timezone.utc)
    version.review_note = note
    # Подтвержденная правка заново заводит удаленный ключ: срок замены был про
    # прежнее значение, как и при прямой записи.
    if secret.deleted and not version.deleted and not version.inherits:
        secret.expires_at = None
    secret.current_version = version.version
    secret.name = version.name_at
    secret.path = version.path_at
    secret.deleted = version.deleted


async def reject_version(
    session: AsyncSession, version: SecretVersion, *, reviewer: str, note: str
) -> None:
    """Отклоненная правка остается в истории: отказ - тоже событие, и по нему
    видно, что предлагали и почему не приняли."""
    await session.refresh(version)
    if version.status != STATUS_PENDING:
        raise NotPending()
    version.status = STATUS_REJECTED
    version.reviewed_by = reviewer
    version.reviewed_at = datetime.now(timezone.utc)
    version.review_note = note


# --- наследование окружений ------------------------------------------------


async def env_chain(session: AsyncSession, env_id: int) -> list[int]:
    """Цепочка окружений от текущего к корню: [свое, родитель, дед...].

    Циклы обрываются молча, а не роняют запрос: испорченная ссылка в базе не
    должна превращаться в отказ всей панели, а увидеть её можно на экране
    окружения - родитель там показан явно.
    """
    chain: list[int] = []
    seen: set[int] = set()
    current: int | None = env_id
    while current is not None and current not in seen:
        chain.append(current)
        seen.add(current)
        env = await session.get(Environment, current)
        current = env.parent_id if env else None
    return chain


async def resolve(
    session: AsyncSession, env_id: int, path: str, name: str
) -> tuple[Secret, int] | None:
    """Ищет ключ в окружении и его родителях. Возвращает (секрет, где нашли).

    Правила простые: свое значение перекрывает родительское; версия "наследуется"
    пропускает окружение и идет выше; удаление перекрывает родителя и на этом
    поиск заканчивается - удалили здесь осознанно, воскрешать значение из
    родителя было бы сюрпризом.
    """
    for level in await env_chain(session, env_id):
        secret = await get_secret(session, level, path, name)
        if secret is None:
            continue
        version = await current_version(session, secret)
        if version is None:
            continue
        if version.inherits:
            continue
        if version.deleted:
            return None
        return secret, level
    return None


async def effective_list(
    session: AsyncSession, env_id: int, memo: dict | None = None
) -> list[tuple[Secret, int]]:
    """Все ключи, которые окружение реально отдает: свои и унаследованные.

    memo - общий запас на несколько окружений одного запроса: строки и версии
    уровня читаются один раз, а не заново в каждом из 25 наследников."""
    out: dict[tuple[str, str], tuple[Secret, int]] = {}
    hidden: set[tuple[str, str]] = set()
    levels: dict[int, tuple[list[Secret], dict[int, SecretVersion]]] = (
        {} if memo is None else memo.setdefault("levels", {})
    )
    for level in await env_chain(session, env_id):
        if level not in levels:
            rows = list(
                await session.scalars(select(Secret).where(Secret.environment_id == level))
            )
            levels[level] = (rows, await current_versions(session, [secret.id for secret in rows]))
        rows, versions = levels[level]
        for secret in rows:
            key = (secret.path, secret.name)
            if key in out or key in hidden:
                continue  # ближе к листу уже решили судьбу этого ключа
            version = versions.get(secret.id)
            if version is None or version.inherits:
                continue
            if version.deleted:
                hidden.add(key)
                continue
            out[key] = (secret, level)
    return sorted(out.values(), key=lambda pair: (pair[0].path, pair[0].name))


async def stop_override(
    session: AsyncSession, box: SealBox, secret: Secret, *, author: str
) -> SecretVersion:
    """Убирает переопределение: ключ снова берется из родительского окружения."""
    await lock_secret(session, secret)
    return await _add_version(
        session,
        box,
        secret,
        value=None,
        name=secret.name,
        path=secret.path,
        deleted=False,
        author=author,
        comment="снято переопределение",
        inherits=True,
    )
