"""Проект с шифрованием в браузере: включить, отдать обертки, добавить машину.

Сервер здесь ничего не шифрует и не расшифровывает. Он хранит обертки ключа
проекта - под паролем для людей и на публичный ключ для машин - и следит за
двумя вещами: что формат похож на правду и что обертку просит тот, кому вообще
разрешено читать этот проект.

Раскрыть обертку панель не может ни при каких правах. Это не ограничение
интерфейса, а то, ради чего режим существует.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from app import access, audit, e2e, secrets_store
from app.deps import CurrentUser, MaintainerUser, SessionDep, peer_ip
from app.models import (
    Environment,
    MachineIdentity,
    Policy,
    Project,
    ProjectKeyWrap,
    Secret,
)

router = APIRouter(prefix="/projects/{project_id}/e2e", tags=["e2e"])

# Обертка под паролем проекта лежит той же таблицей, что и машинные: субъект
# "пароль" один на проект, поэтому номер нулевой.
PASSWORD_SUBJECT = "password"


class InitIn(BaseModel):
    """Все это посчитал браузер. Пароля проекта здесь нет и быть не может."""

    salt: str = Field(min_length=8, max_length=64)
    nonce: str = Field(min_length=8, max_length=64)
    wrapped_key: str = Field(min_length=8, max_length=4000)
    # Маркер проверки: известная строка, запечатанная ключом проекта. По нему
    # браузер понимает, что пароль верный, - не подбирая ключ на значениях.
    verifier_nonce: str = Field(min_length=8, max_length=64)
    verifier: str = Field(min_length=8, max_length=4000)


class WrapOut(BaseModel):
    enabled: bool
    salt: str = ""
    nonce: str = ""
    wrapped_key: str = ""
    verifier_nonce: str = ""
    verifier: str = ""
    iterations: int = e2e.PBKDF2_ITERATIONS


class MachineWrapIn(BaseModel):
    machine_id: int
    # Эфемерный публичный ключ браузера (P-256): по нему агент повторит общий
    # секрет и раскроет обертку.
    ephemeral_public: str = Field(min_length=8, max_length=200)
    nonce: str = Field(min_length=8, max_length=64)
    wrapped_key: str = Field(min_length=8, max_length=4000)


class MachineWrapOut(BaseModel):
    machine_id: int
    name: str
    has_key: bool
    has_wrap: bool


async def _project(session: SessionDep, project_id: int) -> Project:
    project = await session.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    return project


async def _require(session: SessionDep, user, project: Project, action: str) -> None:
    """Право хотя бы в одном окружении проекта.

    Ключ проекта один на все его окружения, а права людям обычно выдают на
    окружение или папку, а не на проект целиком. Проверка на уровне проекта
    пропускала только владельца и тех, кому выдан весь проект: разработчик с
    правом на prod не мог даже отпереть проект в браузере. Запреты действуют как
    везде: решение принимается по месту, куда смотрит разрешение.
    """
    env_ids = list(
        await session.scalars(select(Environment.id).where(Environment.project_id == project.id))
    )
    if await access.visible_in(session, user, action, project.id, env_ids):
        return
    if user.role == access.OWNER:
        return
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        f"Нет права «{access.TITLES.get(action, action)}» в этом проекте",
    )


@router.post("", response_model=WrapOut)
async def init(
    project_id: int,
    body: InitIn,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
) -> WrapOut:
    """Включает режим. Только для пустого проекта.

    Пустого - потому что иначе в одном проекте оказались бы значения двух
    разных видов, и панель показывала бы половину, а половину нет. Перевод
    существующего проекта - это перешифровка всех значений браузером, и делать
    её молча за спиной у человека нельзя.
    """
    project = await _project(session, project_id)
    await _require(session, user, project, access.WRITE)
    # Режим и пароль - на весь проект и навсегда: права на одно окружение
    # мало, иначе ответственный за stage ставил бы свой пароль проекту, где
    # prod ведут другие. То же правило, что для заведения окружений.
    from app.api.projects import _managed_projects

    if project.id not in await _managed_projects(session, user, {project.id}):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Шифрование в браузере включает владелец панели или тот, кому проект выдан целиком на запись",
        )
    # Строка проекта - на запись (новое окружение в это время не заводится),
    # окружения - под блокировкой по возрастанию номера, как у всех записей:
    # запись значения проверяет режим под блокировкой своего окружения, и
    # открытый текст, начатый раньше, виден проверке "проект пуст" ниже, а
    # начатый позже дожидается коммита и видит режим.
    project = await session.scalar(
        select(Project)
        .where(Project.id == project.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    for env_lock in sorted(
        await session.scalars(select(Environment.id).where(Environment.project_id == project.id))
    ):
        await secrets_store.lock_env(session, env_lock)
    if project.e2e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Режим уже включён")

    envs = [e.id for e in await session.scalars(
        select(Environment).where(Environment.project_id == project.id)
    )]
    if envs:
        # Удаленные ключи тоже: их история хранит открытые значения, и откат или
        # снимок вернули бы открытый текст в проект, где его быть не должно.
        existing = await session.scalar(select(Secret).where(Secret.environment_id.in_(envs)))
        if existing is not None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "В проекте уже есть ключи: включить шифрование в браузере можно "
                "только у пустого проекта",
            )
    try:
        e2e.check_wrap(body.nonce, body.wrapped_key)
        e2e.check_wrap(body.verifier_nonce, body.verifier)
    except e2e.FormatError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    project.e2e = True
    session.add(
        ProjectKeyWrap(
            project_id=project.id,
            subject_type=PASSWORD_SUBJECT,
            subject_id=0,
            nonce=body.nonce,
            # Соль и маркер живут рядом с оберткой: это одно и то же знание -
            # "как из пароля получить ключ и как понять, что он верный".
            wrapped_key="\x1f".join(
                (body.wrapped_key, body.salt, body.verifier_nonce, body.verifier)
            ),
        )
    )
    await audit.record(
        session,
        actor=user.username,
        action="e2e_enabled",
        target=project.slug,
        detail="значения шифруются в браузере, сервер их не видит",
        ip=peer_ip(request),
    )
    # Еще раз перед коммитом: на Postgres запись значения ждет строку проекта
    # (см. выше), а там, где блокировок строк нет, открытый текст мог
    # закоммититься после первой проверки.
    if envs and await session.scalar(select(Secret.id).where(Secret.environment_id.in_(envs)).limit(1)):
        await session.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "В проекте уже есть ключи: включить шифрование в браузере можно "
            "только у пустого проекта",
        )
    await session.commit()
    return WrapOut(
        enabled=True,
        salt=body.salt,
        nonce=body.nonce,
        wrapped_key=body.wrapped_key,
        verifier_nonce=body.verifier_nonce,
        verifier=body.verifier,
    )


@router.get("", response_model=WrapOut)
async def get_wrap(project_id: int, user: CurrentUser, session: SessionDep) -> WrapOut:
    """Обертка ключа проекта под паролем. Без пароля она бесполезна."""
    project = await _project(session, project_id)
    # Право сначала, ответ потом: иначе чужой проект отвечал бы "шифрования
    # нет", а проект с шифрованием - отказом, и по разнице было бы видно, где что.
    await _require(session, user, project, access.LIST)
    if not project.e2e:
        return WrapOut(enabled=False)
    row = await session.scalar(
        select(ProjectKeyWrap).where(
            ProjectKeyWrap.project_id == project.id,
            ProjectKeyWrap.subject_type == PASSWORD_SUBJECT,
        )
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Обёртка ключа проекта потеряна")
    parts = row.wrapped_key.split("\x1f")
    wrapped, salt = parts[0], parts[1] if len(parts) > 1 else ""
    verifier_nonce = parts[2] if len(parts) > 2 else ""
    verifier = parts[3] if len(parts) > 3 else ""
    return WrapOut(
        enabled=True,
        salt=salt,
        nonce=row.nonce,
        wrapped_key=wrapped,
        verifier_nonce=verifier_nonce,
        verifier=verifier,
    )


@router.get("/machines", response_model=list[MachineWrapOut])
async def list_machines(
    project_id: int, user: MaintainerUser, session: SessionDep
) -> list[MachineWrapOut]:
    """Машины, которым выдан доступ в этот проект, и есть ли у них ключ проекта.

    Машина без обертки увидит шифротекст и ничего с ним не сделает - это самая
    частая ошибка в таком режиме, и она должна быть видна глазами.
    """
    project = await _project(session, project_id)
    await _require(session, user, project, access.LIST)
    envs = {
        e.id
        for e in await session.scalars(
            select(Environment).where(Environment.project_id == project.id)
        )
    }
    wraps = {
        w.subject_id
        for w in await session.scalars(
            select(ProjectKeyWrap).where(
                ProjectKeyWrap.project_id == project.id,
                ProjectKeyWrap.subject_type == "machine",
            )
        )
    }
    out: list[MachineWrapOut] = []
    seen: set[int] = set()
    for policy in await session.scalars(
        select(Policy).where(Policy.subject_type == "machine", Policy.effect == "allow")
    ):
        if policy.environment_id not in envs and policy.project_id != project.id:
            continue
        if policy.subject_id in seen:
            continue
        machine = await session.get(MachineIdentity, policy.subject_id)
        if machine is None:
            continue
        seen.add(machine.id)
        out.append(
            MachineWrapOut(
                machine_id=machine.id,
                name=machine.name,
                has_key=bool(machine.public_key),
                has_wrap=machine.id in wraps,
            )
        )
    return sorted(out, key=lambda m: m.name)


@router.post("/machines", response_model=MachineWrapOut)
async def add_machine_wrap(
    project_id: int,
    body: MachineWrapIn,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
) -> MachineWrapOut:
    """Кладет ключ проекта, запечатанный на публичный ключ машины.

    Запечатал браузер; панель хранит результат и раскрыть его не может. Именно
    поэтому режим и называется так, как называется.
    """
    project = await _project(session, project_id)
    await _require(session, user, project, access.WRITE)
    if not project.e2e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "У проекта нет шифрования в браузере")
    machine = await session.get(MachineIdentity, body.machine_id)
    if machine is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Машина не найдена")
    # Ключ проекта открывает машине все, что ей выдано в проекте: выдавать его
    # может тот, кто сам читает все, что она, как и прочие ее учетные данные.
    from app.api.machines_admin import _require_reach

    await _require_reach(session, user, [machine.id])
    if not machine.public_key:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "У машины ещё нет ключа: агент присылает его при первом обращении",
        )
    try:
        e2e.check_wrap(body.nonce, body.wrapped_key)
        e2e.check_public_key(body.ephemeral_public)
    except e2e.FormatError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    await session.execute(
        delete(ProjectKeyWrap).where(
            ProjectKeyWrap.project_id == project.id,
            ProjectKeyWrap.subject_type == "machine",
            ProjectKeyWrap.subject_id == machine.id,
        )
    )
    session.add(
        ProjectKeyWrap(
            project_id=project.id,
            subject_type="machine",
            subject_id=machine.id,
            nonce=body.nonce,
            wrapped_key="\x1f".join((body.wrapped_key, body.ephemeral_public)),
        )
    )
    await audit.record(
        session,
        actor=user.username,
        action="e2e_machine_wrapped",
        target=project.slug,
        detail=machine.name,
        ip=peer_ip(request),
    )
    await session.commit()
    return MachineWrapOut(
        machine_id=machine.id, name=machine.name, has_key=True, has_wrap=True
    )
