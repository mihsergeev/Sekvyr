"""Права: политики и группы.

Раздает их владелец панели. Не потому, что ответственный не справится, а потому
что право выдать право - это и есть главный доступ: имея его, можно тихо выписать
себе все остальное.

Политика читается одной строкой: "кому - где - что можно (или нельзя) - до
какого числа". Все, что делает этот роутер, - заводит и убирает такие строки;
решение, кого пускать, живет в app/access.py и одинаково для всех маршрутов.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import access, audit, machines
from app.roles import VIEWER
from app.audit import to_utc
from app.deps import CurrentUser, OwnerUser, SessionDep, peer_ip
from app.models import (
    Environment,
    Group,
    GroupMember,
    MachineIdentity,
    Policy,
    Project,
    User,
)

router = APIRouter(tags=["access"])


class PolicyIn(BaseModel):
    subject_type: str = Field(pattern="^(user|group|machine)$")
    subject_id: int
    project_id: int | None = None
    environment_id: int | None = None
    path_prefix: str = Field(default="/", max_length=200)
    actions: list[str] = Field(min_length=1)
    effect: str = Field(default="allow", pattern="^(allow|deny)$")
    # ISO-8601 или пусто. Пусто = бессрочно.
    expires_at: str = ""
    require_2fa: bool = False


class PolicyOut(BaseModel):
    id: int
    subject_type: str
    subject_id: int
    subject_name: str
    project_id: int | None
    project_slug: str
    environment_id: int | None
    environment_name: str
    path_prefix: str
    actions: list[str]
    effect: str
    expires_at: str
    require_2fa: bool
    created_by: str
    expired: bool


class GroupOut(BaseModel):
    id: int
    name: str
    members: list[str]


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class MemberIn(BaseModel):
    user_id: int


class PermissionsOut(BaseModel):
    """Что текущий человек может в этом окружении. Нужно интерфейсу, чтобы не
    рисовать кнопки, которые все равно ответят отказом."""

    list: bool
    read: bool
    write: bool
    delete: bool
    rotate: bool
    approve: bool


def _parse_expires(raw: str) -> datetime | None:
    if not raw.strip():
        return None
    # Сразу в UTC, как у машин (machines_admin._parse_moment).
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return (
            value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        )
    except (ValueError, OverflowError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Дату окончания не разобрать"
        ) from exc


async def _describe(session: SessionDep, policy: Policy) -> PolicyOut:
    if policy.subject_type == "user":
        subject = await session.get(User, policy.subject_id)
        subject_name = subject.username if subject else f"#{policy.subject_id}"
    elif policy.subject_type == "machine":
        machine = await session.get(MachineIdentity, policy.subject_id)
        subject_name = machine.name if machine else f"#{policy.subject_id}"
    else:
        group = await session.get(Group, policy.subject_id)
        subject_name = group.name if group else f"#{policy.subject_id}"
    project = await session.get(Project, policy.project_id) if policy.project_id else None
    env = (
        await session.get(Environment, policy.environment_id)
        if policy.environment_id
        else None
    )
    expires = policy.expires_at
    now = datetime.now(timezone.utc)
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return PolicyOut(
        id=policy.id,
        subject_type=policy.subject_type,
        subject_id=policy.subject_id,
        subject_name=subject_name,
        project_id=policy.project_id,
        project_slug=project.slug if project else "",
        environment_id=policy.environment_id,
        environment_name=env.name if env else "",
        path_prefix=policy.path_prefix,
        actions=sorted(access.policy_actions(policy)),
        effect=policy.effect,
        expires_at=to_utc(policy.expires_at).isoformat() if policy.expires_at else "",
        require_2fa=policy.require_2fa,
        created_by=policy.created_by,
        expired=bool(expires and expires <= now),
    )


@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(
    _: OwnerUser,
    session: SessionDep,
    subject_type: str = Query(default=""),
    subject_id: int = Query(default=0),
) -> list[PolicyOut]:
    query = select(Policy).order_by(Policy.id)
    if subject_type:
        query = query.where(Policy.subject_type == subject_type)
    if subject_id:
        query = query.where(Policy.subject_id == subject_id)
    return [await _describe(session, p) for p in await session.scalars(query)]


@router.post("/policies", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyIn, request: Request, user: OwnerUser, session: SessionDep
) -> PolicyOut:
    unknown = set(body.actions) - set(access.ACTIONS)
    if unknown:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Неизвестные действия: {sorted(unknown)}"
        )
    if body.subject_type == "user":
        target = await session.get(User, body.subject_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Учётная запись не найдена")
        # Лишнее право наблюдателю все равно не подействует (см. access.py), и
        # выдавать его значило бы показывать в "Доступе" запись, которой нет.
        if target.role == VIEWER and set(body.actions) - access.VIEWER_ACTIONS:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Наблюдателю выдаются только «видеть ключи» и «читать значения»",
            )
    elif body.subject_type == "machine":
        if await session.get(MachineIdentity, body.subject_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Машина не найдена")
        # Машине выдается только чтение, и отказ здесь - часть конструкции, а не
        # придирка: маршрутов, которые пишут значения, в машинном контуре нет
        # вовсе, и право на запись было бы обещанием, которого некому выполнить.
        forbidden = set(body.actions) - set(machines.MACHINE_ACTIONS)
        if forbidden:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Машине можно выдать только чтение, а не {sorted(forbidden)}",
            )
    elif await session.get(Group, body.subject_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Группа не найдена")

    # Окружение однозначно задает проект. Разрешить их расхождение значило бы
    # завести политику, которая никогда ни на что не действует, и потом искать,
    # почему у человека нет доступа.
    if body.environment_id is not None:
        env = await session.get(Environment, body.environment_id)
        if env is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
        if body.project_id is not None and env.project_id != body.project_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Окружение принадлежит другому проекту"
            )
        project_id = env.project_id
    else:
        project_id = body.project_id
        if project_id is not None and await session.get(Project, project_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")

    policy = Policy(
        subject_type=body.subject_type,
        subject_id=body.subject_id,
        project_id=project_id,
        environment_id=body.environment_id,
        path_prefix=access.normalize_prefix(body.path_prefix),
        actions=",".join(sorted(set(body.actions))),
        effect=body.effect,
        expires_at=_parse_expires(body.expires_at),
        require_2fa=body.require_2fa,
        created_by=user.username,
    )
    session.add(policy)
    await session.flush()
    described = await _describe(session, policy)
    await audit.record(
        session,
        actor=user.username,
        action="policy_created",
        target=f"{described.subject_type}:{described.subject_name}",
        detail=f"{described.effect} {','.join(described.actions)} "
        f"{described.project_slug or 'все проекты'}"
        f"{'/' + described.environment_name if described.environment_name else ''}"
        f"{described.path_prefix}",
        ip=peer_ip(request),
    )
    await session.commit()
    return described


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: int, request: Request, user: OwnerUser, session: SessionDep
) -> None:
    policy = await session.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Право не найдено")
    described = await _describe(session, policy)
    await session.delete(policy)
    await audit.record(
        session,
        actor=user.username,
        action="policy_deleted",
        target=f"{described.subject_type}:{described.subject_name}",
        detail=f"{described.effect} {','.join(described.actions)}",
        ip=peer_ip(request),
    )
    await session.commit()


# --- группы ----------------------------------------------------------------


@router.get("/groups", response_model=list[GroupOut])
async def list_groups(_: OwnerUser, session: SessionDep) -> list[GroupOut]:
    out: list[GroupOut] = []
    for group in await session.scalars(select(Group).order_by(Group.name)):
        member_ids = list(
            await session.scalars(
                select(GroupMember.user_id).where(GroupMember.group_id == group.id)
            )
        )
        names = list(
            await session.scalars(select(User.username).where(User.id.in_(member_ids or [-1])))
        )
        out.append(GroupOut(id=group.id, name=group.name, members=sorted(names)))
    return out


@router.post("/groups", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    body: GroupIn, request: Request, user: OwnerUser, session: SessionDep
) -> GroupOut:
    exists = await session.scalar(select(Group).where(Group.name == body.name))
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Группа с таким именем уже есть")
    group = Group(name=body.name)
    session.add(group)
    await session.flush()
    await audit.record(
        session, actor=user.username, action="group_created", target=body.name, ip=peer_ip(request)
    )
    await session.commit()
    return GroupOut(id=group.id, name=group.name, members=[])


@router.post("/groups/{group_id}/members", status_code=status.HTTP_204_NO_CONTENT)
async def add_member(
    group_id: int, body: MemberIn, request: Request, user: OwnerUser, session: SessionDep
) -> None:
    group = await session.get(Group, group_id)
    member = await session.get(User, body.user_id)
    if group is None or member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Группа или учётная запись не найдена")
    exists = await session.scalar(
        select(GroupMember).where(
            GroupMember.group_id == group_id, GroupMember.user_id == body.user_id
        )
    )
    if exists is None:
        session.add(GroupMember(group_id=group_id, user_id=body.user_id))
        await audit.record(
            session,
            actor=user.username,
            action="group_member_added",
            target=group.name,
            detail=member.username,
            ip=peer_ip(request),
        )
    await session.commit()


@router.delete(
    "/groups/{group_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def remove_member(
    group_id: int, user_id: int, request: Request, user: OwnerUser, session: SessionDep
) -> None:
    group = await session.get(Group, group_id)
    member = await session.get(User, user_id)
    row = await session.scalar(
        select(GroupMember).where(
            GroupMember.group_id == group_id, GroupMember.user_id == user_id
        )
    )
    if row is None or group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Такого участника в группе нет")
    await session.delete(row)
    await audit.record(
        session,
        actor=user.username,
        action="group_member_removed",
        target=group.name,
        detail=member.username if member else str(user_id),
        ip=peer_ip(request),
    )
    await session.commit()


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: int, request: Request, user: OwnerUser, session: SessionDep
) -> None:
    """Вместе с группой уходят и выданные ей права: иначе остались бы политики,
    указывающие в пустоту, и "почему у него доступ" стало бы неотвечаемым."""
    group = await session.get(Group, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Группа не найдена")
    name = group.name
    for policy in await session.scalars(
        select(Policy).where(Policy.subject_type == "group", Policy.subject_id == group_id)
    ):
        await session.delete(policy)
    await session.delete(group)
    await audit.record(
        session, actor=user.username, action="group_deleted", target=name, ip=peer_ip(request)
    )
    await session.commit()


# --- "что я могу" ----------------------------------------------------------


@router.get("/environments/{env_id}/permissions", response_model=PermissionsOut)
async def my_permissions(
    env_id: int,
    user: CurrentUser,
    session: SessionDep,
    path: str = Query(default="/", max_length=200),
) -> PermissionsOut:
    env = await session.get(Environment, env_id)
    if env is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
    # Окружение, где у человека нет вообще никаких прав, для него не существует:
    # так же, как проект, которого нет в его списке.
    anywhere = [
        action
        for action in access.ACTIONS
        if await access.visible_in(session, user, action, env.project_id, [env.id])
    ]
    if not anywhere:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
    # Права в папке: у того, кому выдана одна папка, на корне прав нет, а в
    # своей папке есть (история ключа спрашивает про папку ключа).
    scope = access.Scope(project_id=env.project_id, environment_id=env.id, path=path or "/")
    checks = {
        action: await access.allowed(session, user, action, scope) for action in access.ACTIONS
    }
    return PermissionsOut(**checks)
