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

from app import access
from app.access import Scope
from app.models import MachineIdentity, Policy

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
    return decide(await policies_for(session, machine), action, scope, datetime.now(timezone.utc))


async def place_check(
    session: AsyncSession, machine: MachineIdentity, action: str, project_id: int, env_id: int
) -> access.PlaceCheck:
    """Решатель по путям окружения для машины: запрет на папку в машинной
    политике должен действовать и в выдаче окружения целиком."""
    policies = await policies_for(session, machine)
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
    policies = await policies_for(session, machine)
    now = datetime.now(timezone.utc)
    return any(
        decide(policies, action, Scope(project_id=project_id, environment_id=env_id, path=path), now)
        for path in access.interesting_paths(policies, [])
    )
