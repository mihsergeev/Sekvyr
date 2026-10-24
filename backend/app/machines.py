"""Машинные личности: токены, белый список адресов, права.

Отдельный модуль, а не часть `security.py`: у машин другой жизненный цикл
(секрет живет годами, токен - минуты), другой способ отзыва (версия токена у
самой личности) и другая модель угроз - машина не забудет пароль, но её токен
может уехать в лог сборки.

Права машины - те же политики, что у людей, с одним отличием: машине можно
выдать только чтение. Это не настройка, а свойство конструкции, и его держит
`ops/selfcheck.py`.
"""

from __future__ import annotations

import ipaddress
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import access, roles
from app.access import Scope
from app.models import Cluster, MachineIdentity, Policy, User

# Машине доступны только эти действия. Список короткий и намеренно жесткий:
# `write`, `delete`, `rotate` и `approve` не выдаются в принципе, даже если
# кто-то попробует сохранить такую политику через API.
MACHINE_ACTIONS = (access.LIST, access.READ)

# Токен машины живет минуты: он ездит в заголовках сборок и попадает в логи
# чаще, чем хотелось бы. Долгоживущий здесь - секрет, и он остается на машине.
TOKEN_TTL_MINUTES = 15

_PREFIX = "machine:"


def new_credentials() -> tuple[str, str]:
    """Пара "идентификатор + секрет". Секрет показывается ровно один раз."""
    return f"skv-{secrets.token_hex(8)}", secrets.token_urlsafe(36)


def token_subject(machine: MachineIdentity) -> str:
    return _PREFIX + machine.client_id


def create_token(machine: MachineIdentity, jwt_secret: str) -> tuple[str, int]:
    """Короткий токен доступа и его срок в секундах."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": token_subject(machine),
        "mid": machine.id,
        "ver": machine.token_version,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, jwt_secret, algorithm="HS256"), TOKEN_TTL_MINUTES * 60


def decode_token(token: str, jwt_secret: str) -> dict | None:
    """Payload машинного токена или None. Токен человека сюда не пройдет: у
    него нет приставки `machine:`, и это единственное место, где они
    различаются."""
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub.startswith(_PREFIX):
        return None
    return payload


def ip_allowed(allow_ips: str, ip: str) -> bool:
    """Пустой список означает "откуда угодно".

    Список читается слева направо, поддерживает и адрес, и подсеть. Строка,
    которую не удалось разобрать, не пропускает никого: тихо считать её "всеми"
    значило бы превращать опечатку в открытую дверь.
    """
    entries = allow_ips.split()
    if not entries:
        return True
    try:
        peer = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in entries:
        try:
            if peer in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def alive(machine: MachineIdentity, now: datetime | None = None) -> bool:
    moment = now or datetime.now(timezone.utc)
    if machine.disabled:
        return False
    if machine.expires_at is None:
        return True
    expires = machine.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > moment


async def policies_for(session: AsyncSession, machine: MachineIdentity) -> list[Policy]:
    rows = await session.scalars(
        select(Policy).where(
            Policy.subject_type == "machine", Policy.subject_id == machine.id
        )
    )
    return list(rows)


def may_vouch(user: User | None, without: str = "") -> bool:
    """Может ли человек отвечать за доступ машины: учетка есть, не отключена и
    роль не ниже ответственного. Те же условия, что у токена подключения
    (api/machine.py, _creator_still_may): заводят машины и выдают им права
    ответственный и выше. without - имя, которое считать уже отключенным
    (сколько машин встанет, если отключить этого человека)."""
    if user is None or user.disabled or (without and user.username == without):
        return False
    return roles.level(user.role) >= roles.level(roles.MAINTAINER)


def _reads_all(
    user: User, user_policies: list[Policy], policy: Policy, denies: list[Policy], now: datetime
) -> bool:
    """Читает ли человек сейчас все, что машине открывает эта политика (с
    учетом запретов самой машины). Сравнение во всех местах, где решение
    может меняться, как в access.covers, но только в момент "сейчас": право
    машины проверяется на каждом обращении и кончается вместе с правом того,
    кто его выдал."""
    if user.role == access.OWNER:
        return True
    target = [policy, *denies]
    pairs = {(p.project_id, p.environment_id) for p in [*user_policies, *target]}
    paths = access.interesting_paths([*user_policies, *target], [])
    for project_id, env_id in pairs:
        for path in paths:
            scope = Scope(project_id=project_id, environment_id=env_id, path=path)
            for action in MACHINE_ACTIONS:
                if decide(target, action, scope, now) and not access.decide(
                    user_policies, user, action, scope, now
                ):
                    return False
    return True


async def effective_policies(
    session: AsyncSession,
    machine: MachineIdentity,
    *,
    without: str = "",
    people: dict | None = None,
) -> list[Policy]:
    """Политики машины, которые действуют сейчас.

    Право машины держится на людях. Разрешение действует, пока тот, кто его
    выдал, может выдать его и сейчас: учетка не отключена, роль не ниже
    ответственного и сам читает все, что выдал. Иначе отключенный или
    лишенный окружения человек продолжал бы читать его через свою машину.
    Кроме того, машина не получает ничего, если отключен или понижен тот, кто
    ее завел (у него ее секрет), а у машины за подом - тот, кто завел ее
    кластер (он распоряжается ключами кластера). Запреты действуют всегда.

    people - общий на один запрос словарь учеток с их политиками: список
    серверов спрашивает об одних и тех же людях для каждой машины.
    """
    cache = people if people is not None else {}

    async def person(name: str) -> tuple[User | None, list[Policy]]:
        if name not in cache:
            user = await session.scalar(select(User).where(User.username == name))
            cache[name] = (user, await access.policies_for(session, user) if user else [])
        return cache[name]

    policies = await policies_for(session, machine)
    denies = [p for p in policies if p.effect != "allow"]
    keepers = [machine.created_by]
    if machine.cluster_id is not None:
        cluster = await session.get(Cluster, machine.cluster_id)
        keepers.append(cluster.created_by if cluster else "")
    for name in keepers:
        user, _ = await person(name)
        if not may_vouch(user, without):
            return denies
    now = datetime.now(timezone.utc)
    out = list(denies)
    for policy in policies:
        if policy.effect != "allow":
            continue
        user, user_policies = await person(policy.created_by)
        if may_vouch(user, without) and _reads_all(user, user_policies, policy, denies, now):
            out.append(policy)
    return out


async def resting_on(session: AsyncSession, username: str) -> list[MachineIdentity]:
    """Живые машины, которые потеряют хоть одно окружение, если этот человек
    больше не сможет выдавать доступ (его отключат или понизят): он их завел,
    завел их кластер или выдал им права. По этому списку отключение учетки
    говорит, сколько серверов и кластеров перестанут получать значения."""
    granted = select(Policy.subject_id).where(
        Policy.subject_type == "machine", Policy.created_by == username
    )
    clusters = select(Cluster.id).where(Cluster.created_by == username)
    rows = await session.scalars(
        select(MachineIdentity)
        .where(
            (MachineIdentity.created_by == username)
            | MachineIdentity.id.in_(granted)
            | MachineIdentity.cluster_id.in_(clusters)
        )
        .order_by(MachineIdentity.id)
    )
    people: dict = {}
    now = datetime.now(timezone.utc)
    out: list[MachineIdentity] = []
    for machine in rows:
        if not alive(machine):
            continue

        def working(policies: list[Policy]) -> set[int]:
            return {p.id for p in policies if p.effect == "allow" and access.alive(p, now)}

        before = working(await effective_policies(session, machine, people=people))
        after = working(
            await effective_policies(session, machine, without=username, people=people)
        )
        if before - after:
            out.append(machine)
    return out


def decide(policies: list[Policy], action: str, scope: Scope, now: datetime) -> bool:
    """Решение для машины по уже загруженным политикам."""
    if action not in MACHINE_ACTIONS:
        return False
    matched = [p for p in policies if access.alive(p, now) and access.matches(p, action, scope)]
    if any(p.effect == "deny" for p in matched):
        return False
    return any(p.effect == "allow" for p in matched)


async def allowed(
    session: AsyncSession, machine: MachineIdentity, action: str, scope: Scope
) -> bool:
    """Разрешено ли машине действие. Владельца-исключения здесь нет: машина не
    бывает владельцем панели, и "все можно" для нее не существует."""
    return decide(
        await effective_policies(session, machine), action, scope, datetime.now(timezone.utc)
    )


async def place_check(
    session: AsyncSession, machine: MachineIdentity, action: str, project_id: int, env_id: int
) -> access.PlaceCheck:
    """Решатель по путям окружения для машины: запрет на папку в машинной
    политике должен действовать и в выдаче окружения целиком."""
    policies = await effective_policies(session, machine)
    now = datetime.now(timezone.utc)
    cache: dict[str, bool] = {}

    def check(path: str) -> bool:
        if path not in cache:
            cache[path] = decide(
                policies, action, Scope(project_id=project_id, environment_id=env_id, path=path), now
            )
        return cache[path]

    return check


async def sees_anything(
    session: AsyncSession, machine: MachineIdentity, action: str, project_id: int, env_id: int
) -> bool:
    """Есть ли у машины право хоть на одну папку окружения. Политика только на
    /app раньше не давала ничего: проверялся корень."""
    policies = await effective_policies(session, machine)
    now = datetime.now(timezone.utc)
    return any(
        decide(policies, action, Scope(project_id=project_id, environment_id=env_id, path=path), now)
        for path in access.interesting_paths(policies, [])
    )
