"""Учетные записи людей.

Правило одно и работает во всех маршрутах: распоряжаться можно только тем, чья
роль СТРОГО ниже твоей, и выдать можно только роль строго ниже своей. Из него
следуют сразу три вещи, которые иначе пришлось бы проверять отдельно: нельзя
повысить себя, нельзя тронуть равного и нельзя завести себе преемника с теми же
правами, обойдя владельца.

Учетки не удаляются, а отключаются. Удаление увело бы за собой имя из журнала,
а журнал должен оставаться читаемым и через год: "кто в марте открывал прод" -
это вопрос про человека, которого уже нет в компании.
"""

import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app import access, audit, roles
from app.audit import to_utc
from app.db import bump_token_version
from app.deps import MaintainerUser, SessionDep, peer_ip
from app.models import User
from app.security import MIN_PASSWORD_LEN, hash_password_async

router = APIRouter(prefix="/users", tags=["users"])


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    role_title: str
    disabled: bool
    totp_enabled: bool
    # Откуда пускать: адреса и подсети через пробел. Пусто - откуда угодно.
    allow_ips: str = ""
    created_at: str


class UserIn(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=MIN_PASSWORD_LEN, max_length=256)
    role: str = Field(default=roles.VIEWER)


class UserPatch(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    allow_ips: str | None = Field(default=None, max_length=500)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=MIN_PASSWORD_LEN, max_length=256)


def _out(u: User) -> UserOut:
    return UserOut(
        id=u.id,
        username=u.username,
        role=u.role,
        role_title=roles.TITLES.get(u.role, u.role),
        disabled=u.disabled,
        totp_enabled=u.totp_enabled,
        allow_ips=u.allow_ips,
        created_at=to_utc(u.created_at).isoformat() if u.created_at else "",
    )


def _require_outranks(actor: User, target: User) -> None:
    if not roles.outranks(actor.role, target.role):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Распоряжаться можно только учётками с ролью ниже своей",
        )


def _require_grantable(actor: User, role: str) -> None:
    if role not in roles.ALL:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестная роль")
    if roles.level(role) >= roles.level(actor.role):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Нельзя выдать роль вровень со своей или выше"
        )


COVER_DENIED = (
    "У этой учетной записи есть права, которых нет у вас: задать ей пароль может "
    "тот, у кого они тоже есть, или владелец"
)


async def _require_cover(session: SessionDep, actor: User, target: User) -> None:
    """Задать чужой пароль - значит войти под этим именем со всеми его правами.
    Поэтому можно только тому, кто и сам может все, что может эта учетка:
    иначе ответственный без доступа к проду входил бы туда через разработчика.
    То же правило, что у машин (machines_admin._require_reach)."""
    if actor.role == roles.OWNER:
        return
    now = datetime.now(timezone.utc)
    mine = await access.policies_for(session, actor)
    theirs = await access.policies_for(session, target)
    # Права цели - наибольшие из доступных ей: второй фактор она включит, роль
    # ей повысят (access.potential).
    ghost = access.potential(target)
    # Сравнение во всех местах, где решение может меняться, а не в одной точке
    # на политику: запрет актора на папку внутри разрешения цели иначе не
    # виден, и через сброс пароля читалась закрытая папка.
    # Актор - как есть, без "включит второй фактор": сброс не спрашивает его
    # пароль, и чужая сессия ответственного без 2FA открывала бы права,
    # которые ему самому даются только со вторым фактором. Тот же подход, что
    # у машин (_require_reach). Включить 2FA себе и сбросить потом - можно.
    if not access.covers(
        mine,
        actor,
        theirs,
        lambda action, scope, at: access.decide(theirs, ghost, action, scope, at),
        access.ACTIONS,
        now,
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, COVER_DENIED)


async def _fetch(session: SessionDep, user_id: int) -> User:
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Учётная запись не найдена")
    return target


async def _last_active_owner(session: SessionDep, target: User) -> bool:
    """Остался бы кто-то, кто может распоряжаться панелью, если тронуть этого?"""
    if target.role != roles.OWNER or target.disabled:
        return False
    others = await session.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == roles.OWNER, User.disabled.is_(False), User.id != target.id)
    )
    return not others


@router.get("", response_model=list[UserOut])
async def list_users(_: MaintainerUser, session: SessionDep) -> list[UserOut]:
    rows = await session.scalars(select(User).order_by(User.username))
    return [_out(u) for u in rows]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserIn, request: Request, user: MaintainerUser, session: SessionDep
) -> UserOut:
    _require_grantable(user, body.role)
    exists = await session.scalar(select(User).where(User.username == body.username))
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Такой логин уже занят")
    created = User(
        username=body.username,
        password_hash=await hash_password_async(body.password),
        role=body.role,
    )
    session.add(created)
    await audit.record(
        session,
        actor=user.username,
        action="user_created",
        target=body.username,
        detail=f"роль: {body.role}",
        ip=peer_ip(request),
    )
    await session.commit()
    return _out(created)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int, body: UserPatch, request: Request, user: MaintainerUser, session: SessionDep
) -> UserOut:
    target = await _fetch(session, user_id)
    _require_outranks(user, target)

    changes: list[str] = []
    if body.role is not None and body.role != target.role:
        _require_grantable(user, body.role)
        if await _last_active_owner(session, target):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Это последний владелец панели — роль не менять"
            )
        changes.append(f"роль: {target.role} → {body.role}")
        target.role = body.role
        # роль сменилась - прежние токены больше не отражают правду
        await bump_token_version(session, target)
    if body.disabled is not None and body.disabled != target.disabled:
        if body.disabled and await _last_active_owner(session, target):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Это последний владелец панели — не отключать"
            )
        changes.append("отключена" if body.disabled else "включена")
        target.disabled = body.disabled
        if body.disabled:
            await bump_token_version(session, target)  # разлогинить сразу, а не по сроку токена

    if body.allow_ips is not None:
        fresh = " ".join(body.allow_ips.split())
        if fresh != target.allow_ips:
            # Проверяем разбираемость здесь, а не в момент входа: опечатка в
            # подсети иначе всплывет тем, что человек однажды не войдет, и
            # объяснить это будет некому.
            for entry in fresh.split():
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST, f"Не разобрал адрес: {entry}"
                    ) from None
            changes.append(
                f"адреса: {target.allow_ips or 'откуда угодно'} → {fresh or 'откуда угодно'}"
            )
            target.allow_ips = fresh

    if changes:
        await audit.record(
            session,
            actor=user.username,
            action="user_updated",
            target=target.username,
            detail="; ".join(changes),
            ip=peer_ip(request),
        )
    await session.commit()
    return _out(target)


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    user_id: int,
    body: PasswordReset,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
) -> None:
    """Задать пароль подчиненной учетке - человек забыл свой. Прежние сессии
    закрываются, а сам факт остается в журнале: смена чужого пароля это доступ
    к чужому имени, и она не должна быть тихой."""
    target = await _fetch(session, user_id)
    _require_outranks(user, target)
    await _require_cover(session, user, target)
    target.password_hash = await hash_password_async(body.new_password)
    await bump_token_version(session, target)
    await audit.record(
        session,
        actor=user.username,
        action="user_password_reset",
        target=target.username,
        ip=peer_ip(request),
    )
    await session.commit()
