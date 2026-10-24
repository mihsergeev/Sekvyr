"""Проекты и окружения.

Заводить проекты и окружения может ответственный и выше. Список видит каждый
вошедший, но только те проекты, до которых его допускают политики
(app/access.py).

Создание окружения требует отпертой панели: вместе с окружением заводится
его ключ, а обернуть ключ нечем, пока корневой не введен.
"""

import re

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from sqlalchemy import func

from app import alerts, access, audit, envkeys, naming, roles, secrets_store
from app.audit import to_utc
from app.deps import (
    BoxDep,
    CurrentUser,
    MaintainerUser,
    OwnerUser,
    SessionDep,
    UnsealedBox,
    peer_ip,
)
from app.models import Environment, Project, Secret, SecretVersion

router = APIRouter(tags=["projects"])

# Имя из одного символа тоже годится: окружения вроде "a" и "b" встречаются на
# временных стендах, и запрещать их не за что.
SLUG = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")


def _iso(moment) -> str:
    """Время в ISO с зоной. Без зоны браузер считает его местным, и правка
    часовой давности уезжает на несколько часов. `to_utc` умеет обе формы:
    Postgres отдает метку с зоной, SQLite - без нее."""
    return to_utc(moment).isoformat() if moment else ""


class ProjectIn(BaseModel):
    slug: str = Field(min_length=2, max_length=64)
    title: str = Field(default="", max_length=200)
    group_name: str = Field(default="", max_length=64)
    # Окружения сразу при создании: проект без единого окружения бесполезен, а
    # заводить prod/stage/dev тремя окнами подряд - работа, которую панель
    # может сделать сама.
    environments: list[str] = Field(default_factory=list, max_length=20)


class ProjectOut(BaseModel):
    id: int
    slug: str
    title: str
    e2e: bool
    environments: list[str] = []
    # Уровень роли, ниже которого правки ждут подтверждения. 0 = не ждут.
    approval_min_level: int = 0
    # Ключи, без которых приложение не поднимется: имена через пробел.
    required_keys: str = ""
    # С какого возраста значение считается давним.
    stale_after_days: int = 365
    group_name: str = ""
    # Группа куском адреса: по ней страница проекта находится в адресной строке.
    group_slug: str = ""
    # Закрытый проект: в списке он лежит отдельно, а не вперемешку с живыми.
    archived: bool = False
    # Когда в проекте последний раз правили ключ. Пусто - ни одной правки не
    # было: проект завели и не наполнили.
    last_change_at: str = ""
    # Счетчики для списка: без них сотня проектов - это сотня одинаковых строк,
    # по которым не видно, где что живет.
    env_count: int = 0
    secret_count: int = 0
    pending_count: int = 0
    # Может ли этот человек заводить окружения в проекте: владелец или право
    # менять проект целиком. Кнопку интерфейс показывает по этому полю, а не
    # по роли.
    manage: bool = False


class ProjectPatch(BaseModel):
    title: str | None = None
    approval_min_level: int | None = None
    group_name: str | None = None
    required_keys: str | None = Field(default=None, max_length=2000)
    stale_after_days: int | None = Field(default=None, ge=1, le=3650)
    archived: bool | None = None


class EnvIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    title: str = Field(default="", max_length=200)
    # Скопировать значения из этого окружения. Не то же, что родитель: копия
    # живет своей жизнью, а наследник смотрит в родителя каждый раз.
    copy_from: int | None = None
    # Родительское окружение: свои значения перекрывают его, остальное берется
    # оттуда. Для десятка одинаковых стендов это разница между одним паролем и
    # десятью копиями, которые расходятся молча.
    parent_id: int | None = None


class EnvPatch(BaseModel):
    title: str | None = None
    parent_id: int | None = None


class EnvOut(BaseModel):
    # Сколько значений скопировали при создании. Ноль - окружение пустое.
    copied: int = 0
    id: int
    project_id: int
    name: str
    title: str
    key_generation: int
    parent_id: int | None = None
    parent_name: str = ""
    secret_count: int = 0
    own_count: int = 0


def _check_slug(slug: str, what: str = "проекта") -> None:
    if not SLUG.match(slug):
        # Что именно не понравилось, должно быть видно из ответа: одно и то же
        # сообщение про "имя проекта" при создании окружения сбивает с толку.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Имя {what}: строчные латинские буквы, цифры и дефис",
        )


# Сколько прежних групп помнить. Переезжают проекты редко, а агент со
# старым адресом, переживший пять переездов, - это уже забытый сервер.
MOVED_FROM_KEEP = 5


def _remember_move(moved_from: str, old: str, new: str) -> str:
    """Прежние группы проекта после переезда из old в new.

    "-" значит "без группы": агент, подключенный к проекту без группы, помнит
    адрес без нее. Группа, куда проект вернулся, из списка уходит: ее адрес
    снова его собственный, и подставлять туда нечего.
    """
    old, new = old or "-", new or "-"
    kept = [slug for slug in moved_from.split() if slug not in (old, new)]
    kept.append(old)
    return " ".join(kept[-MOVED_FROM_KEEP:])


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(user: CurrentUser, session: SessionDep) -> list[ProjectOut]:
    # Показываем только те проекты, куда есть хоть какой-то доступ. Список чужих
    # проектов с отказом на каждом клике - это и подсказка о том, что вообще
    # существует в компании, и просто раздражение.
    visible = await access.visible_projects(session, user)
    projects = list(
        await session.scalars(select(Project).order_by(Project.group_name, Project.slug))
    )
    if visible is not None:
        projects = [p for p in projects if p.id in visible]
    envs = list(await session.scalars(select(Environment).order_by(Environment.position)))
    # Окружения и счетчики - только видимые: имена, число ключей, ожидающие
    # правки и время последней правки чужого окружения тоже сведения, а
    # список окружений проекта эту утечку уже закрывал.
    shown = await _visible_env_ids(session, user, envs, {p.id for p in projects})
    managed = await _managed_projects(session, user, {p.id for p in projects})
    by_project: dict[int, list[str]] = {}
    env_project: dict[int, int] = {}
    for env in envs:
        if env.id not in shown:
            continue
        by_project.setdefault(env.project_id, []).append(env.name)
        env_project[env.id] = env.project_id

    # Счетчики считаем разом двумя запросами, а не по проекту: на сотне проектов
    # с десятком окружений в каждом поштучный подсчет превращает открытие
    # главной в сотни запросов.
    counts: dict[int, int] = {}
    shown_envs = [env for env in envs if env.id in env_project]
    for env_id, total in (await _own_counts(session, user, shown_envs)).items():
        counts[env_project[env_id]] = counts.get(env_project[env_id], 0) + total

    waiting: dict[int, int] = {}
    # Как и число ключей - только в видимых папках: три предложения в закрытой
    # папке тоже сведения о ней.
    can_list = await access.place_checks(session, user, access.LIST, [(e.project_id, e.id) for e in shown_envs])
    for env_id, path, total in await session.execute(
        select(Secret.environment_id, Secret.path, func.count())
        .join(SecretVersion, SecretVersion.secret_id == Secret.id)
        .where(SecretVersion.status == secrets_store.STATUS_PENDING)
        .group_by(Secret.environment_id, Secret.path)
    ):
        if env_id not in env_project or not can_list[env_id](path):
            continue
        project_id = env_project[env_id]
        waiting[project_id] = waiting.get(project_id, 0) + total

    # Когда в проекте последний раз что-то правили. Тем же способом, что и
    # счетчики: один запрос на весь список, а не по запросу на проект.
    touched: dict[int, object] = {}
    # По видимым папкам, как счетчики: время правки в закрытой папке - тоже
    # сведения о ней.
    for env_id, path, last in await session.execute(
        select(Secret.environment_id, Secret.path, func.max(SecretVersion.created_at))
        .join(SecretVersion, SecretVersion.secret_id == Secret.id)
        .group_by(Secret.environment_id, Secret.path)
    ):
        if last is None or env_id not in env_project or not can_list[env_id](path):
            continue
        project_id = env_project[env_id]
        known = touched.get(project_id)
        if known is None or last > known:
            touched[project_id] = last

    return [
        ProjectOut(
            id=p.id,
            slug=p.slug,
            title=p.title,
            e2e=p.e2e,
            environments=by_project.get(p.id, []),
            approval_min_level=p.approval_min_level,
            required_keys=p.required_keys,
            stale_after_days=p.stale_after_days,
            group_name=p.group_name,
            group_slug=p.group_slug,
            archived=p.archived,
            last_change_at=_iso(touched.get(p.id)),
            env_count=len(by_project.get(p.id, [])),
            secret_count=counts.get(p.id, 0),
            pending_count=waiting.get(p.id, 0),
            manage=p.id in managed,
        )
        for p in projects
    ]


@router.post("/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectIn,
    request: Request,
    user: OwnerUser,
    session: SessionDep,
    box: BoxDep,
) -> ProjectOut:
    _check_slug(body.slug)
    group_name = body.group_name.strip()
    group_slug = naming.slugify(group_name)
    if group_slug:
        # "Globex" и "globex" дают один и тот же кусок адреса, то есть
        # это одна группа. Написание берем у той, что уже есть: иначе список
        # проектов рисует два одинаковых заголовка, между которыми нет разницы.
        neighbour = await session.scalar(
            select(Project).where(Project.group_slug == group_slug).limit(1)
        )
        if neighbour is not None:
            group_name = neighbour.group_name
    exists = await session.scalar(
        select(Project).where(Project.group_slug == group_slug, Project.slug == body.slug)
    )
    if exists is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "В этой группе уже есть проект с таким именем"
            if group_name
            else "Проект с таким именем уже есть",
        )

    names = [name.strip() for name in body.environments if name.strip()]
    if names and not box.unsealed:
        # Окружение без ключа завести нельзя, а ключ нечем обернуть, пока
        # корневой не подан. Отказываем до создания проекта, а не после.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Панель заперта: окружения появятся только после ввода ключа",
        )
    for name in names:
        _check_slug(name, "окружения")
    if len(set(names)) != len(names):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Окружения повторяются")

    project = Project(
        slug=body.slug,
        title=body.title,
        group_name=group_name,
        group_slug=group_slug,
    )
    session.add(project)
    await session.flush()
    # Ключи окружений - до записей журнала: смена корневого ключа берет
    # блокировку ключей, а потом журнала, и обратный порядок здесь давал
    # встречное ожидание.
    created: list[str] = []
    for position, name in enumerate(names):
        env = Environment(project_id=project.id, name=name, title="", position=position)
        session.add(env)
        await session.flush()
        await envkeys.create(session, box, env.id)
        created.append(name)
    await audit.record(
        session,
        actor=user.username,
        action="project_created",
        target=f"{group_slug}/{body.slug}" if group_slug else body.slug,
        ip=peer_ip(request),
    )
    for name in created:
        await audit.record(
            session,
            actor=user.username,
            action="environment_created",
            target=f"{project.slug}/{name}",
            ip=peer_ip(request),
        )
    await session.commit()
    return ProjectOut(
        id=project.id,
        slug=project.slug,
        title=project.title,
        e2e=project.e2e,
        approval_min_level=project.approval_min_level,
        required_keys=project.required_keys,
        stale_after_days=project.stale_after_days,
        group_name=project.group_name,
        group_slug=project.group_slug,
        environments=created,
        env_count=len(created),
    )


@router.patch("/projects/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: int,
    body: ProjectPatch,
    request: Request,
    user: OwnerUser,
    session: SessionDep,
) -> ProjectOut:
    """Порог согласования и название проекта.

    Порог задает владелец панели, а не ответственный за проект: иначе тот, чьи
    правки должны подтверждаться, первым делом отключил бы подтверждение.
    """
    project = await session.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    changes: list[str] = []
    if body.title is not None and body.title != project.title:
        project.title = body.title
        changes.append("название")
    if body.group_name is not None and body.group_name.strip() != project.group_name:
        group_name = body.group_name.strip()
        group_slug = naming.slugify(group_name)
        # Переезд в другую группу - это смена адреса проекта, и там может уже
        # лежать тезка. Проверяем до записи, иначе ответом была бы ошибка базы.
        taken = await session.scalar(
            select(Project).where(
                Project.group_slug == group_slug,
                Project.slug == project.slug,
                Project.id != project.id,
            )
        )
        if taken is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "В этой группе уже есть проект с таким именем"
            )
        if group_slug and group_slug == project.group_slug:
            # Слаг тот же, поменялось написание - это переименование ГРУППЫ, а
            # не переезд одного проекта. Разное написание у соседей означало бы
            # два заголовка на один адрес.
            for neighbour in await session.scalars(
                select(Project).where(Project.group_slug == group_slug)
            ):
                neighbour.group_name = group_name
        elif group_slug:
            # Переезд в существующую группу - берем её написание.
            neighbour = await session.scalar(
                select(Project).where(Project.group_slug == group_slug).limit(1)
            )
            if neighbour is not None:
                group_name = neighbour.group_name
        if group_slug != project.group_slug:
            # Прежний адрес запоминаем: агенты на серверах держат его в
            # конфиге, и без этого перенос отключил бы их все разом.
            project.moved_from = _remember_move(
                project.moved_from, project.group_slug, group_slug
            )
        project.group_name = group_name
        project.group_slug = group_slug
        changes.append("группа")
    if body.approval_min_level is not None:
        level = body.approval_min_level
        if level and level not in roles.LEVELS.values():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестный уровень роли")
        if level != project.approval_min_level:
            changes.append(f"порог согласования: {project.approval_min_level} → {level}")
            project.approval_min_level = level
    if body.required_keys is not None:
        # Имена через пробел: порядок и повторы нормализуем, чтобы "список
        # изменился" не срабатывало от лишнего пробела.
        fresh = " ".join(body.required_keys.split())
        if fresh != project.required_keys:
            changes.append(f"обязательные ключи: {len(fresh.split())} шт.")
            project.required_keys = fresh
    if body.archived is not None and body.archived != project.archived:
        # Отдельной записи в журнале не заводим: это та же правка проекта, и
        # искать её будут там же, где смену порога или переезд в группу.
        changes.append("в архив" if body.archived else "из архива")
        project.archived = body.archived
    if body.stale_after_days is not None and body.stale_after_days != project.stale_after_days:
        changes.append(
            f"давним считается старше: {project.stale_after_days} → {body.stale_after_days} дн."
        )
        project.stale_after_days = body.stale_after_days
    if changes:
        await audit.record(
            session,
            actor=user.username,
            action="project_updated",
            target=project.slug,
            detail="; ".join(changes),
            ip=peer_ip(request),
        )
    await session.commit()
    envs = list(
        await session.scalars(
            select(Environment).where(Environment.project_id == project_id)
        )
    )
    return ProjectOut(
        id=project.id,
        slug=project.slug,
        title=project.title,
        e2e=project.e2e,
        environments=[e.name for e in envs],
        approval_min_level=project.approval_min_level,
        required_keys=project.required_keys,
        stale_after_days=project.stale_after_days,
        group_name=project.group_name,
        group_slug=project.group_slug,
        archived=project.archived,
        env_count=len(envs),
    )


class EnvBriefOut(BaseModel):
    """Окружение одной строкой: "группа/проект/окружение"."""

    id: int
    name: str
    project_slug: str
    group_slug: str = ""
    title: str = ""


@router.get("/environments", response_model=list[EnvBriefOut])
async def list_all_environments(user: CurrentUser, session: SessionDep) -> list[EnvBriefOut]:
    """Все окружения, которые человеку видно.

    Нужен формам, где окружение выбирают из списка, а не ищут по проектам:
    иначе выбор одного места превращается в два вложенных выпадающих списка.
    Фильтр по правам здесь тот же, что и везде: нет права видеть ключи - нет и
    строки в списке.
    """
    out: list[EnvBriefOut] = []
    projects = {p.id: p for p in await session.scalars(select(Project))}
    rows = await session.scalars(select(Environment).order_by(Environment.id))
    for env in rows:
        project = projects.get(env.project_id)
        if project is None:
            continue
        # Право хоть на одну папку: с правом только на /app окружения в этом
        # списке не было, хотя открыть его человек мог.
        if env.id not in await access.visible_in(session, user, access.LIST, project.id, [env.id]):
            continue
        out.append(
            EnvBriefOut(
                id=env.id,
                name=env.name,
                project_slug=project.slug,
                group_slug=project.group_slug,
                title=env.title,
            )
        )
    return out


ENV_CREATE_DENIED = (
    "Окружения в проекте заводит владелец панели или тот, у кого есть право "
    "менять проект целиком"
)


async def _managed_projects(session, user, project_ids: set[int]) -> set[int]:
    """Проекты, где человек может заводить окружения: право "менять" на
    проект без привязки к окружению. Право на одно окружение не дает заводить
    соседние - иначе ответственный с доступом к prod заводил qa, которого сам
    потом не видел, и мог заводить окружения в проекте, которого не видит."""
    if user.role == roles.OWNER:
        return set(project_ids)
    # Скрытый запретом проект (общее разрешение и запрет на этот проект) -
    # тоже не его: иначе в невидимом проекте заводились окружения, а 409 на
    # занятое имя выдавал, какие там есть.
    visible = await access.visible_projects(session, user)
    policies = await access.policies_for(session, user)
    now = datetime.now(timezone.utc)
    return {
        pid
        for pid in project_ids
        if (visible is None or pid in visible)
        and access.decide(policies, user, access.WRITE, access.Scope(project_id=pid, environment_id=None, path="/"), now)
    }


async def _own_counts(session, user, envs: list[Environment]) -> dict[int, int]:
    """Свои ключи окружений одним запросом: без удаленных, взятых у родителя и
    новых, которые еще ждут подтверждения (ключом они станут после него). Не
    владельцу - только в видимых папках: число ключей закрытой папки - тоже
    сведения о ней."""
    checks = await access.place_checks(session, user, access.LIST, [(e.project_id, e.id) for e in envs])
    out: dict[int, int] = {}
    for env_id, path, total in await session.execute(
        select(Secret.environment_id, Secret.path, func.count())
        .where(
            Secret.environment_id.in_([e.id for e in envs] or [-1]),
            Secret.deleted.is_(False),
            Secret.current_version > 0,
        )
        .group_by(Secret.environment_id, Secret.path)
    ):
        if checks[env_id](path):
            out[env_id] = out.get(env_id, 0) + total
    return out


async def _visible_env_ids(session, user, envs: list[Environment], project_ids: set[int]) -> set[int]:
    """Видимые окружения всех показанных проектов разом: политики загружаются
    один раз, а не на каждый проект главной страницы."""
    if user.role == roles.OWNER:
        return {env.id for env in envs}
    policies = await access.policies_for(session, user)
    now = datetime.now(timezone.utc)
    paths = access.interesting_paths(policies, [])
    out: set[int] = set()
    for env in envs:
        if env.project_id not in project_ids:
            continue
        for path in paths:
            scope = access.Scope(project_id=env.project_id, environment_id=env.id, path=path)
            if access.decide(policies, user, access.LIST, scope, now) or access.decide(
                policies, user, access.READ, scope, now
            ):
                out.add(env.id)
                break
    return out


async def _visible_envs(session, user, project_id: int, env_ids: list[int]) -> set[int]:
    """Окружения проекта, где есть право видеть ключи или читать значения."""
    return await access.visible_in(
        session, user, access.LIST, project_id, env_ids
    ) | await access.visible_in(session, user, access.READ, project_id, env_ids)


@router.get("/projects/{project_id}/environments", response_model=list[EnvOut])
async def list_environments(
    project_id: int, user: CurrentUser, session: SessionDep
) -> list[EnvOut]:
    rows = list(
        await session.scalars(
            select(Environment)
            .where(Environment.project_id == project_id)
            .order_by(Environment.position, Environment.id)
        )
    )
    # Видно только то, где есть право видеть ключи или читать значения хоть в
    # какой-то папке. Раньше этот маршрут отдавал окружения любого проекта по
    # номеру: имена, наследование и число ключей там, где список проектов этот
    # проект прятал.
    visible = await _visible_envs(session, user, project_id, [e.id for e in rows])
    if not visible and user.role != roles.OWNER:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    rows = [e for e in rows if e.id in visible]
    names = {e.id: e.name for e in rows}
    own = await _own_counts(session, user, rows)
    checks = await access.place_checks(session, user, access.LIST, [(e.project_id, e.id) for e in rows])

    out: list[EnvOut] = []
    # Строки и версии родителя - один раз на запрос, а не в каждом наследнике:
    # проект на 30 окружений по 5000 ключей отвечал до 11 с ради одних чисел.
    memo: dict = {}
    for e in rows:
        # Сколько ключей окружение реально отдает (со всем унаследованным) и
        # сколько задано в нем самом. Разница и есть ответ на вопрос "что здесь
        # свое, а что пришло сверху".
        effective = sum(
            1
            for secret, _level in await secrets_store.effective_list(session, e.id, memo)
            if checks[e.id](secret.path)
        )
        own_count = own.get(e.id, 0)
        out.append(
            EnvOut(
                id=e.id,
                project_id=e.project_id,
                name=e.name,
                title=e.title,
                key_generation=0,
                parent_id=e.parent_id,
                parent_name=names.get(e.parent_id or -1, ""),
                secret_count=effective,
                own_count=own_count,
            )
        )
    return out


@router.post(
    "/projects/{project_id}/environments",
    response_model=EnvOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_environment(
    project_id: int,
    body: EnvIn,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
    box: UnsealedBox,
) -> EnvOut:
    project = await session.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    # Сначала права, потом все остальное: ответ "такое окружение уже есть"
    # иначе называл бы окружения чужого проекта.
    if project_id not in await _managed_projects(session, user, {project_id}):
        visible = await access.visible_projects(session, user)
        if visible is not None and project_id not in visible:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
        raise HTTPException(status.HTTP_403_FORBIDDEN, ENV_CREATE_DENIED)
    _check_slug(body.name, "окружения")
    exists = await session.scalar(
        select(Environment).where(
            Environment.project_id == project_id, Environment.name == body.name
        )
    )
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Такое окружение уже есть")

    parent_id = await _check_parent(session, project_id, body.parent_id, None)
    if parent_id is not None and not await _reads_whole(
        session, user, await session.get(Environment, parent_id)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, WHOLE_PARENT)
    source = None
    if body.copy_from:
        source = await session.get(Environment, body.copy_from)
        if source is None or source.project_id != project_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Копировать можно из окружения этого проекта"
            )
        if project.e2e:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "В проекте с шифрованием в браузере значения копируются из браузера",
            )
        if not await _reads_whole(session, user, source):
            raise HTTPException(status.HTTP_403_FORBIDDEN, WHOLE_COPY)
    count = len(list(await session.scalars(
        select(Environment).where(Environment.project_id == project_id)
    )))
    # Строка проекта - под блокировкой ключа: удаление проекта, закоммиченное
    # после проверок выше, иначе давало 500 на внешнем ключе, а начатое позже
    # дождется этого коммита и снесет окружение вместе с проектом.
    if (
        await session.scalar(
            select(Project.id).where(Project.id == project_id).with_for_update(read=True, key_share=True)
        )
        is None
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    env = Environment(
        project_id=project_id,
        name=body.name,
        title=body.title,
        position=count,
        parent_id=parent_id,
    )
    session.add(env)
    await session.flush()
    # ключ окружения заводится сразу: окружение без ключа - это окружение, в
    # которое нельзя ничего записать, и такое состояние никому не нужно
    generation, _key = await envkeys.create(session, box, env.id)
    await audit.record(
        session,
        actor=user.username,
        action="environment_created",
        target=f"{project.slug}/{body.name}",
        ip=peer_ip(request),
    )
    # Копия значений: берем то, что окружение-источник реально отдает, включая
    # унаследованное, - новое окружение должно подняться само по себе, а не
    # зависеть от чужого родителя.
    copied = 0
    if source is not None:
        plain = await secrets_store.values_of(session, box, source.id)
        for secret, _level in await secrets_store.effective_list(session, source.id):
            value = plain.get((secret.path, secret.name))
            if value is None:
                continue
            await secrets_store.set_value(
                session,
                box,
                env_id=env.id,
                path=secret.path,
                name=secret.name,
                value=value,
                author=user.username,
                comment=f"копия из {source.name}",
                pending=False,
                legacy_name=True,
            )
            copied += 1
        await audit.record(
            session,
            actor=user.username,
            action="env_copied",
            target=f"{project.slug}/{body.name}",
            detail=f"из {source.name}, ключей {copied}",
            ip=peer_ip(request),
        )

    await session.commit()
    return EnvOut(
        id=env.id,
        project_id=project_id,
        name=env.name,
        title=env.title,
        key_generation=generation,
        parent_id=env.parent_id,
        copied=copied,
    )


class ProjectExportOut(BaseModel):
    text: str
    # Окружения, которые в файл не попали: нет права читать или шифрование в
    # браузере. Молчать о них нельзя - иначе неполный файл считают полным.
    skipped: list[str] = []


@router.get("/projects/{project_id}/export", response_model=ProjectExportOut)
async def export_project(
    project_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> ProjectExportOut:
    """Все окружения проекта одним файлом.

    Выгрузка по одному стенду уже была, но проект на два десятка окружений так
    не собрать - а собирают его ровно тогда, когда проект переезжает или его
    разбирают после инцидента.

    Каждое окружение идет своим блоком с заголовком-комментарием: файл читается
    глазами и режется на части одной командой. Права спрашиваются на каждое
    окружение отдельно, и пропущенные названы в ответе.
    """
    project = await session.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    envs = list(
        await session.scalars(
            select(Environment)
            .where(Environment.project_id == project_id)
            .order_by(Environment.position, Environment.id)
        )
    )
    # Окружения, которых человеку не видно, не попадают и в список пропущенных:
    # иначе выгрузка чужого проекта перечисляла бы его окружения по именам.
    visible = await _visible_envs(session, user, project_id, [e.id for e in envs])
    if not visible and user.role != roles.OWNER:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")

    parts: list[str] = []
    skipped: list[str] = []
    taken = 0
    # Значения родителя открываются один раз на всю выгрузку, а не в каждом
    # наследнике: проект на 30 окружений выгружался 108 с и упирался в 504.
    memo: dict = {}
    for env in envs:
        if env.id not in visible:
            continue
        # Окружение целиком - только если читаются все его папки, как у
        # выгрузки одного окружения: запрет на /pay обходился выгрузкой проекта.
        paths = await secrets_store.env_paths(session, env.id)
        if not await access.covers_whole(session, user, access.READ, project_id, env.id, paths):
            skipped.append(env.name)
            continue
        try:
            text = await secrets_store.export_env(session, box, env.id, memo=memo)
        except secrets_store.SealedValueRequired:
            skipped.append(env.name)
            continue
        parts.append(f"# --- {project.slug}/{env.name} ---\n{text}")
        taken += 1

    await audit.record(
        session,
        actor=user.username,
        action="project_exported",
        target=project.slug,
        detail=f"окружений {taken}, пропущено {len(skipped)}",
        ip=peer_ip(request),
    )
    await session.commit()
    return ProjectExportOut(text="\n".join(parts), skipped=skipped)


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: int,
    request: Request,
    user: OwnerUser,
    session: SessionDep,
    confirm: str = "",
) -> None:
    """Удаление проекта со всеми окружениями, ключами и их историей.

    Требует передать имя проекта в `confirm`: это единственная операция панели,
    после которой значения исчезают безвозвратно, и она не должна получаться
    случайным нажатием. Восстановление - только из бэкапа базы.
    """
    project = await session.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    if confirm != project.slug:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Для удаления подтвердите имя проекта: {project.slug}",
        )
    slug = project.slug
    await session.delete(project)
    await audit.record(
        session,
        actor=user.username,
        action="project_deleted",
        target=slug,
        detail="вместе с окружениями, ключами и историей",
        ip=peer_ip(request),
    )
    await session.commit()
    # Единственная операция, после которой значения исчезают навсегда: о ней
    # узнают сразу, а не когда сервис не поднимется.
    await alerts.notify(
        session,
        f"🗑 Sekvyr: {user.username} удалил проект «{slug}» вместе со всеми "
        "окружениями, ключами и историей",
    )


WHOLE_PARENT = (
    "Родителем можно назначить только окружение, которое вы читаете целиком: "
    "его значения увидит каждый, кто читает наследника"
)
WHOLE_COPY = "Скопировать можно только окружение, которое вы читаете целиком"


async def _reads_whole(session, user, env: Environment) -> bool:
    """Читает ли человек окружение целиком: каждую папку, включая унаследованное.

    Наследник отдает значения родителя всем, кто читает его самого, людям и
    машинам, а копия уносит их насовсем. Поэтому и то, и другое можно только
    тому, кто сам прочитал бы каждое значение: иначе нехватка права на соседнее
    окружение или запрет на папку обходились бы одной правкой окружения.
    """
    # Папки и ключей, и политик: запрет на пустую пока папку иначе не виден, а
    # ключ, положенный туда потом, наследник отдавал бы.
    paths = await secrets_store.env_paths(session, env.id)
    return await access.covers_whole(session, user, access.READ, env.project_id, env.id, paths)


async def _check_parent(
    session: SessionDep, project_id: int, parent_id: int | None, env_id: int | None
) -> int | None:
    """Проверяет, что родитель годится: свой проект, не сам себе и без цикла.

    Цикл здесь не теоретический: два стенда легко назначить родителями друг
    друга, и тогда чтение любого ключа уходит в бесконечность. Ломать это лучше
    на входе, а не разбирать потом по зависшим запросам.
    """
    if parent_id is None:
        return None
    parent = await session.get(Environment, parent_id)
    if parent is None or parent.project_id != project_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Родителем может быть окружение того же проекта"
        )
    if env_id is not None:
        if parent_id == env_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Окружение не наследует само себя")
        seen = {env_id}
        current: int | None = parent_id
        while current is not None:
            if current in seen:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, "Так получится круг наследования"
                )
            seen.add(current)
            node = await session.get(Environment, current)
            current = node.parent_id if node else None
    return parent_id


@router.patch("/environments/{env_id}", response_model=EnvOut)
async def update_environment(
    env_id: int,
    body: EnvPatch,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
) -> EnvOut:
    """Название и родитель окружения.

    Родитель меняется, только если поле передано: правка одного названия не
    должна молча снимать наследование.
    """
    env = await session.get(Environment, env_id)
    if env is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
    await access.require(
        session,
        user,
        access.WRITE,
        access.Scope(project_id=env.project_id, environment_id=env.id, path="/"),
    )
    changes: list[str] = []
    reparent = "parent_id" in body.model_fields_set and body.parent_id != env.parent_id
    if reparent:
        # Окружения проекта - под блокировкой и по возрастанию номера, до
        # проверки цикла и до любой правки строки: встречные правки (prod от
        # stage и stage от prod) иначе обе не видели цикла, а название,
        # ушедшее в базу раньше, брало строку окружения вне порядка.
        for neighbour_id in sorted(
            await session.scalars(
                select(Environment.id).where(Environment.project_id == env.project_id)
            )
        ):
            await secrets_store.lock_env(session, neighbour_id)
    if body.title is not None and body.title != env.title:
        env.title = body.title
        changes.append("название")
    if reparent and body.parent_id != env.parent_id:
        # Смена родителя меняет значения наследника сразу и ждать
        # подтверждения не умеет: ниже порога проекта она обходила бы его,
        # как удаление или импорт.
        from app.api.secrets import refuse_below_threshold

        await refuse_below_threshold(session, user, env)
        parent_id = await _check_parent(session, env.project_id, body.parent_id, env_id)
        old = await session.get(Environment, env.parent_id) if env.parent_id else None
        new = await session.get(Environment, parent_id) if parent_id else None
        if new is not None and not await _reads_whole(session, user, new):
            raise HTTPException(status.HTTP_403_FORBIDDEN, WHOLE_PARENT)
        # Смена родителя меняет значения во всех папках наследника сразу:
        # унаследованное пропадает, новое появляется, в том числе там, где
        # менять человеку запрещено. Право на корень этого не покрывает.
        paths = await secrets_store.env_paths(session, env.id)
        if new is not None:
            paths |= await secrets_store.env_paths(session, new.id)
        if not await access.covers_whole(
            session, user, access.WRITE, env.project_id, env.id, paths
        ):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f'В окружении есть папки, где у вас нет права "{access.TITLES[access.WRITE]}": '
                "действие над всем окружением недоступно",
            )
        changes.append(
            f"родитель: {old.name if old else 'нет'} → {new.name if new else 'нет'}"
        )
        env.parent_id = parent_id
    if changes:
        await audit.record(
            session,
            actor=user.username,
            action="environment_updated",
            target=str(env_id),
            detail="; ".join(changes),
            ip=peer_ip(request),
        )
    await session.commit()
    parent = await session.get(Environment, env.parent_id) if env.parent_id else None
    return EnvOut(
        id=env.id,
        project_id=env.project_id,
        name=env.name,
        title=env.title,
        key_generation=0,
        parent_id=env.parent_id,
        parent_name=parent.name if parent else "",
        secret_count=len(await secrets_store.effective_list(session, env.id)),
    )
