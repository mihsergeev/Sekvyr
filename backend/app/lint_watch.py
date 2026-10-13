"""Панель сама замечает новые косяки в значениях и говорит о них.

Замечание, которое видно только тому, кто зашел в окружение, - это половина
пользы. `changeme`, появившийся в проде вечером пятницы, должен догнать
человека там, где он есть, а не ждать, пока кто-нибудь откроет страницу.

Сообщение уходит одно на весь обход и только про то, чего раньше не было:
повторять список каждые несколько часов - верный способ научить людей не читать
эти сообщения. Значения в сообщение не попадают: только место и текст
замечания.

Обход возможен, лишь пока панель распечатана - значения приходится
расшифровывать. У запертой панели проверка молчит: это не отказ, а следствие
того, что она в принципе не может прочитать ни одного значения.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import alerts, crypto, envkeys, lint, secrets_store
from app.audit import to_utc
from app.models import Environment, LintMute, LintSeen, Project, Secret
from app.sealbox import SealBox

log = logging.getLogger("sekvyr.lint")

# Шесть часов: замечание - не авария, за которой бегут ночью, но и ждать сутки
# незачем. Обход стоит расшифровки всех значений, чаще его гонять не стоит.
CHECK_INTERVAL = 6 * 60 * 60

# За сколько дней предупреждать о сроке замены. Две недели - столько обычно
# занимает "выпустить новый токен и разложить его по стендам", если заниматься
# этим не в последний вечер.
WARN_BEFORE_DAYS = 14

# Код, под которым панель помнит, что о сроке уже говорила.
EXPIRY_CODE = "expiry_soon"

# Сколько строк показываем в сообщении. Остальное - числом: список на сорок
# строк в мессенджере читают так же, как не читают вовсе.
IN_MESSAGE = 10


async def _collect(session: AsyncSession, box: SealBox) -> list[tuple[int, str, lint.Note]]:
    """Замечания уровня "почти наверняка ошибка" по всем окружениям.

    Принятые ("так и надо") пропускаем: человек уже сказал про них, что так и
    задумано, и напоминать об этом в мессенджере - то же самое, что показывать
    их на экране.
    """
    out: list[tuple[int, str, lint.Note]] = []

    muted = {
        (row.environment_id, row.path, row.name, row.code)
        for row in await session.scalars(select(LintMute))
    }

    projects = {p.id: p for p in await session.scalars(select(Project))}
    for environment in await session.scalars(select(Environment)):
        project = projects.get(environment.project_id)
        if project is None or project.e2e:
            # Значения проекта шифрует браузер: сервер видит шифротекст, и
            # "замечания" к нему были бы замечаниями к случайным байтам.
            continue

        where = (
            f"{project.group_slug}/{project.slug}/{environment.name}"
            if project.group_slug
            else f"{project.slug}/{environment.name}"
        )
        for secret, _level in await secrets_store.effective_list(session, environment.id):
            try:
                value = await secrets_store.read_value(session, box, secret)
            except (envkeys.MissingKeyError, crypto.DecryptionError, secrets_store.SecretNotFound):
                # Одно нечитаемое значение не останавливает обход всей панели.
                continue
            for note in lint.inspect(secret.name, secret.path, value, environment.name):
                if note.level != "bad":
                    continue
                if (environment.id, note.path, note.name, note.code) in muted:
                    continue
                out.append((environment.id, where, note))
    return out


async def _expiring(session: AsyncSession) -> list[tuple[int, str, str, str, date]]:
    """Ключи, срок замены которых подходит или уже прошел.

    Значения не читаются: срок лежит у самого ключа, и знать, что внутри, для
    этого не нужно. Поэтому проверка работает и у запертой панели.
    """
    edge = datetime.now(timezone.utc) + timedelta(days=WARN_BEFORE_DAYS)
    out: list[tuple[int, str, str, str, date]] = []
    projects = {p.id: p for p in await session.scalars(select(Project))}
    environments = {e.id: e for e in await session.scalars(select(Environment))}
    rows = await session.scalars(
        select(Secret).where(
            Secret.deleted.is_(False),
            Secret.expires_at.is_not(None),
            Secret.expires_at <= edge,
        )
    )
    for secret in rows:
        environment = environments.get(secret.environment_id)
        project = projects.get(environment.project_id) if environment else None
        if environment is None or project is None:
            continue
        where = (
            f"{project.group_slug}/{project.slug}/{environment.name}"
            if project.group_slug
            else f"{project.slug}/{environment.name}"
        )
        out.append(
            (
                environment.id,
                where,
                secret.path,
                secret.name,
                to_utc(secret.expires_at).date(),
            )
        )
    return out


async def _live_envs(session: AsyncSession, env_ids: set[int]) -> set[int]:
    if not env_ids:
        return set()
    return set(await session.scalars(select(Environment.id).where(Environment.id.in_(env_ids))))


async def sweep_expiry(session_factory) -> int:
    """Сообщить о новых подходящих сроках. Возвращает их число."""
    async with session_factory() as session:
        found = await _expiring(session)
        alive = {(env_id, path, name) for env_id, _where, path, name, _day in found}
        known = {
            (row.environment_id, row.path, row.name): row
            for row in await session.scalars(
                select(LintSeen).where(LintSeen.code == EXPIRY_CODE)
            )
        }
        for place, row in known.items():
            if place not in alive:
                # Значение заменили или срок отодвинули: если он снова подойдет,
                # напомнить стоит заново.
                await session.delete(row)

        fresh = [
            (where, path, name, day)
            for env_id, where, path, name, day in found
            if (env_id, path, name) not in known
        ]
        marks = [
            (env_id, path, name)
            for env_id, _where, path, name, _day in found
            if (env_id, path, name) not in known
        ]
        await session.commit()

    if not fresh:
        return 0

    today = datetime.now(timezone.utc).date()
    lines = [f"Скоро менять значения: {len(fresh)}"]
    for where, path, name, day in fresh[:IN_MESSAGE]:
        place = name if path == "/" else f"{path}/{name}"
        left = (day - today).days
        when = "срок прошёл" if left < 0 else ("сегодня" if left == 0 else f"через {left} дн.")
        lines.append(f"{where} · {place} — {day.isoformat()} ({when})")
    if len(fresh) > IN_MESSAGE:
        lines.append(f"…и ещё {len(fresh) - IN_MESSAGE}")

    # Отметка "сказано" - только после доставки: канал, лежавший в момент
    # обхода, иначе съедал напоминание навсегда.
    if not await alerts.notify_later(session_factory, "\n".join(lines)):
        return 0
    async with session_factory() as session:
        # Окружение могли удалить, пока шла отправка: отметка для него упала
        # бы на внешнем ключе и унесла бы с собой остальные.
        live = await _live_envs(session, {env_id for env_id, _path, _name in marks})
        for env_id, path, name in marks:
            if env_id in live:
                session.add(LintSeen(environment_id=env_id, path=path, name=name, code=EXPIRY_CODE))
        await session.commit()
    return len(fresh)


async def sweep(session_factory, box: SealBox) -> int:
    """Один обход. Возвращает число новых замечаний - для тестов и логов."""
    if not box.unsealed:
        return 0

    async with session_factory() as session:
        found = await _collect(session, box)
        alive = {(env_id, note.path, note.name, note.code) for env_id, _where, note in found}

        known = {
            (row.environment_id, row.path, row.name, row.code): row
            for row in await session.scalars(select(LintSeen))
        }

        # Исчезнувшие забываем: если ту же ошибку повторят через месяц, о ней
        # стоит сказать снова.
        # Отметки о сроке замены ведет sweep_expiry, а не этот обход: стирая их
        # здесь, он заставлял напоминание о том же сроке приходить каждые
        # шесть часов.
        for place, row in known.items():
            if place not in alive and row.code != EXPIRY_CODE:
                await session.delete(row)

        fresh = [
            (where, note)
            for env_id, where, note in found
            if (env_id, note.path, note.name, note.code) not in known
        ]
        marks = [
            (env_id, note.path, note.name, note.code)
            for env_id, _where, note in found
            if (env_id, note.path, note.name, note.code) not in known
        ]
        await session.commit()

    if not fresh:
        return 0

    lines = [f"Новые замечания к значениям: {len(fresh)}"]
    for where, note in fresh[:IN_MESSAGE]:
        place = note.name if note.path == "/" else f"{note.path}/{note.name}"
        lines.append(f"{where} · {place} — {note.text}")
    if len(fresh) > IN_MESSAGE:
        lines.append(f"…и ещё {len(fresh) - IN_MESSAGE}")

    if not await alerts.notify_later(session_factory, "\n".join(lines)):
        return 0
    async with session_factory() as session:
        live = await _live_envs(session, {env_id for env_id, _path, _name, _code in marks})
        for env_id, path, name, code in marks:
            if env_id in live:
                session.add(LintSeen(environment_id=env_id, path=path, name=name, code=code))
        await session.commit()
    return len(fresh)


async def watch(session_factory, box: SealBox) -> None:
    """Фоновый обход значений."""
    while True:
        try:
            count = await sweep(session_factory, box)
            if count:
                log.info("новых замечаний к значениям: %s", count)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - обход не должен ронять панель
            log.warning("обход значений не удался", exc_info=True)
        # Сроки проверяются отдельно и всегда: значения для этого не нужны, и
        # запертая панель о сроке все равно напомнит. В том же try одна битая
        # версия в обходе значений глушила и все напоминания о сроках.
        try:
            due = await sweep_expiry(session_factory)
            if due:
                log.info("подходящих сроков замены: %s", due)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.warning("проверка сроков замены не удалась", exc_info=True)
        await asyncio.sleep(CHECK_INTERVAL)
