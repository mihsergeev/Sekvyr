"""Машинные личности со стороны панели: завести, отозвать, посмотреть.

Это админский контур, а не машинный: здесь пишут, поэтому маршруты лежат под
`/api/machines`, за белым списком адресов, и требуют роли ответственного. Сам
машинный контур (`/api/v1/machine`) не умеет ни создавать личности, ни менять
им права - см. `app/api/machine.py`.
"""

import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from app import access, audit, geoip, kube, machines, secrets_store
from app.audit import to_utc
from app.db import bump_token_version
from app.deps import MaintainerUser, SessionDep, peer_ip
from app.config import get_settings
from app.models import (
    Cluster,
    EnrollToken,
    Environment,
    MachineApp,
    MachineIdentity,
    Policy,
    Project,
)
from app.security import generate_token, hash_token

router = APIRouter(prefix="/machines", tags=["machines"])


# Машинами распоряжается ответственный, а значения выдаются только политиками.
# Без проверок ниже роль, которая заводит серверы, обходила бы политики: завел
# машину, подключил ее к чужому окружению, забрал секрет и прочитал значения
# машинным контуром. Поэтому выдать машине можно только то, что читаешь сам, а
# новые учетные данные машины получает только тот, кто читает все, что она.
REACH_DENIED = (
    "Учетные данные этой машины открывают окружение, которое вам не выдано: "
    "распоряжаться ими может тот, кто сам читает это окружение, или владелец"
)


async def _require_read(session, user, environment: Environment) -> None:
    """Выдать машине окружение может только тот, кто его читает сам - целиком:
    машине выдается корень, и через нее читалась бы закрытая для человека
    папка."""
    paths = await secrets_store.env_paths(session, environment.id)
    if not await access.covers_whole(
        session, user, access.READ, environment.project_id, environment.id, paths
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, REACH_DENIED)


def _lives(machine: MachineIdentity | None, at: datetime, expires: object = ...) -> bool:
    """Жива ли машина в момент at по сроку (выключение не в счет: охват решает,
    что она откроет, если ее включат). expires - новый срок из правки."""
    if machine is None:
        return True
    deadline = machine.expires_at if expires is ... else expires
    if deadline is None:
        return True
    return to_utc(deadline) > at


async def _require_reach(
    session, user, machine_ids: list[int], *, expires: dict[int, datetime | None] | None = None
) -> None:
    """Новые учетные данные машины - только тому, кто читает все, что она.

    С учетом срока самой машины: машина, которая умрет раньше права
    ответственного, им покрыта (expires - новый срок из правки машины)."""
    if user.role == access.OWNER or not machine_ids:
        return
    mine = await access.policies_for(session, user)
    now = datetime.now(timezone.utc)
    for machine_id in machine_ids:
        theirs = list(
            await session.scalars(
                select(Policy).where(Policy.subject_type == "machine", Policy.subject_id == machine_id)
            )
        )
        # Право шире одного окружения по окружениям не проверить, а выдает
        # такие права машинам только владелец.
        if any(p.effect == "allow" and p.environment_id is None for p in theirs):
            raise HTTPException(status.HTTP_403_FORBIDDEN, REACH_DENIED)
        machine = await session.get(MachineIdentity, machine_id)
        deadline = (expires or {}).get(machine_id, ...)
        if not access.covers(
            mine,
            user,
            theirs,
            lambda action, scope, at, theirs=theirs, machine=machine, deadline=deadline: (
                _lives(machine, at, deadline) and machines.decide(theirs, action, scope, at)
            ),
            machines.MACHINE_ACTIONS,
            now,
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, REACH_DENIED)


class MachineIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=300)
    # Адреса и подсети через пробел. Пусто - откуда угодно.
    allow_ips: str = Field(default="", max_length=500)
    # ISO-дата или пусто. Личность подрядчика логично заводить со сроком.
    expires_at: str = Field(default="", max_length=40)
    # Личность за подом: вместо секрета - ServiceAccount в кластере. Секрет
    # тогда не выдается вовсе, и хранить на ноде нечего.
    cluster_id: int | None = None
    k8s_namespace: str = Field(default="", max_length=120)
    k8s_service_account: str = Field(default="", max_length=120)


class MachinePatch(BaseModel):
    name: str | None = None
    description: str | None = None
    allow_ips: str | None = None
    expires_at: str | None = None
    disabled: bool | None = None


class MachineAppOut(BaseModel):
    """Приложение на сервере: его окружение и файл, который агент поддерживает.

    Строку пишет сам агент своим отчетом. По ней на странице окружения видно не
    только "кто-то это читает", но и куда значения приезжают.
    """

    environment: str
    path: str = ""
    applied: str = ""
    last_seen_at: str = ""


class MachineOut(BaseModel):
    id: int
    name: str
    client_id: str
    cluster: str = ""
    k8s_namespace: str = ""
    k8s_service_account: str = ""
    description: str = ""
    allow_ips: str = ""
    expires_at: str = ""
    disabled: bool = False
    agent_version: str = ""
    applied: str = ""
    last_seen_at: str = ""
    last_ip: str = ""
    # Страна считается по внешнему адресу офлайн-таблицей: имя сервера в этом не
    # участвует, и "kz-" в начале имени ничего не доказывает.
    country: str = ""
    os: str = ""
    local_ip: str = ""
    created_by: str = ""
    # Куда выдан доступ: "billing/prod". Показывается в списке, чтобы не идти за
    # этим в раздел прав.
    environments: list[str] = []
    # Что сервер на самом деле забирает. Отличается от `environments`: там
    # выданные права, здесь приложения, о которых отчитался агент.
    apps: list[MachineAppOut] = []


class CreatedOut(MachineOut):
    """Секрет отдается ровно один раз - при создании и при перевыпуске.

    У кластерной личности он пустой: там доказательством служит подписанный
    кластером ServiceAccount-токен, а не строка, которую надо где-то хранить.
    """

    client_secret: str = ""


def _parse_moment(value: str) -> datetime | None:
    if not value.strip():
        return None
    # Сразу в UTC: SQLite хранит время без зоны, и +03:00 иначе ложилось
    # местным временем со сдвигом на три часа. Крайняя дата со смещением
    # (9999-12-31T23:00-03:00) не помещается в год 9999 - это ошибка даты, а
    # не "номер вне диапазона".
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (
            moment.replace(tzinfo=timezone.utc)
            if moment.tzinfo is None
            else moment.astimezone(timezone.utc)
        )
    except (ValueError, OverflowError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Дата не разобралась: нужен формат ГГГГ-ММ-ДД"
        ) from exc


def _iso(moment: datetime | None) -> str:
    if moment is None:
        return ""
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).isoformat()


def _ips(raw: str) -> str:
    """Адреса машины одной строкой. Неразобранный адрес не пускает никого, и
    опечатка всплыла бы тем, что сервер однажды перестал получать значения:
    отказываем сразу, как у людей."""
    fresh = " ".join(raw.split())[:500]
    for entry in fresh.split():
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Не разобрал адрес: {entry}") from None
    return fresh


async def _environments(session: SessionDep, machine: MachineIdentity) -> list[str]:
    names: list[str] = []
    now = datetime.now(timezone.utc)
    for policy in await machines.policies_for(session, machine):
        # Истекшее право - уже не "получает окружение".
        if policy.effect != "allow" or policy.environment_id is None or not access.alive(policy, now):
            continue
        environment = await session.get(Environment, policy.environment_id)
        if environment is None:
            continue
        project = await session.get(Project, environment.project_id)
        if project is None:
            names.append(environment.name)
            continue
        # С группой: имя проекта уникально внутри нее, и без группы строка
        # "frontend/prod" подошла бы сразу двум командам.
        prefix = f"{project.group_slug}/" if project.group_slug else ""
        names.append(f"{prefix}{project.slug}/{environment.name}")
    return sorted(set(names))


async def _apps(session: SessionDep, machine: MachineIdentity) -> list[MachineAppOut]:
    rows = await session.scalars(
        select(MachineApp)
        .where(MachineApp.machine_id == machine.id)
        .order_by(MachineApp.project_slug, MachineApp.env_name)
    )
    out: list[MachineAppOut] = []
    for row in rows:
        prefix = f"{row.group_slug}/" if row.group_slug else ""
        out.append(
            MachineAppOut(
                environment=f"{prefix}{row.project_slug}/{row.env_name}",
                path=row.path,
                applied=row.applied,
                last_seen_at=_iso(row.last_seen_at),
            )
        )
    return out


async def _out(session: SessionDep, machine: MachineIdentity) -> MachineOut:
    cluster = (
        await session.get(Cluster, machine.cluster_id) if machine.cluster_id else None
    )
    return MachineOut(
        id=machine.id,
        name=machine.name,
        client_id=machine.client_id,
        cluster=cluster.name if cluster else "",
        k8s_namespace=machine.k8s_namespace,
        k8s_service_account=machine.k8s_service_account,
        description=machine.description,
        allow_ips=machine.allow_ips,
        expires_at=_iso(machine.expires_at),
        disabled=machine.disabled,
        agent_version=machine.agent_version,
        applied=machine.applied,
        last_seen_at=_iso(machine.last_seen_at),
        last_ip=machine.last_ip,
        country=geoip.country_of(machine.last_ip),
        os=machine.os,
        local_ip=machine.local_ip,
        created_by=machine.created_by,
        environments=await _environments(session, machine),
        apps=await _apps(session, machine),
    )


@router.get("", response_model=list[MachineOut])
async def list_machines(user: MaintainerUser, session: SessionDep) -> list[MachineOut]:
    rows = await session.scalars(select(MachineIdentity).order_by(MachineIdentity.name))
    return [await _out(session, machine) for machine in rows]


@router.post("", response_model=CreatedOut, status_code=status.HTTP_201_CREATED)
async def create_machine(
    body: MachineIn, request: Request, user: MaintainerUser, session: SessionDep
) -> CreatedOut:
    client_id, secret = machines.new_credentials()
    kubernetes = body.cluster_id is not None
    if kubernetes:
        if await session.get(Cluster, body.cluster_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Кластер не найден")
        if not body.k8s_namespace.strip() or not body.k8s_service_account.strip():
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Для кластерной личности нужны namespace и ServiceAccount",
            )
        # Вторая личность на тот же ServiceAccount перехватила бы его поды:
        # какую из двух панель найдет по токену, решал бы порядок строк.
        taken = await session.scalar(
            select(MachineIdentity.id)
            .where(
                MachineIdentity.cluster_id == body.cluster_id,
                MachineIdentity.k8s_namespace == body.k8s_namespace.strip(),
                MachineIdentity.k8s_service_account == body.k8s_service_account.strip(),
            )
            .limit(1)
        )
        if taken is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Для этого ServiceAccount машина уже заведена"
            )
        # Секрета нет: пустой хеш не совпадет ни с чем, и войти можно только
        # токеном, подписанным кластером.
        secret = ""
    machine = MachineIdentity(
        name=body.name.strip(),
        client_id=client_id,
        secret_hash=hash_token(secret) if secret else "",
        description=body.description.strip(),
        allow_ips=_ips(body.allow_ips),
        expires_at=_parse_moment(body.expires_at),
        cluster_id=body.cluster_id,
        k8s_namespace=body.k8s_namespace.strip(),
        k8s_service_account=body.k8s_service_account.strip(),
        created_by=user.username,
    )
    session.add(machine)
    await session.flush()
    await audit.record(
        session,
        actor=user.username,
        action="machine_created",
        target=machine.name,
        detail=client_id,
        ip=peer_ip(request),
    )
    await session.commit()
    base = await _out(session, machine)
    return CreatedOut(**base.model_dump(), client_secret=secret)


@router.patch("/{machine_id}", response_model=MachineOut)
async def update_machine(
    machine_id: int,
    body: MachinePatch,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
) -> MachineOut:
    machine = await session.get(MachineIdentity, machine_id)
    if machine is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Машина не найдена")
    ips = _ips(body.allow_ips) if body.allow_ips is not None else machine.allow_ips
    expires = _parse_moment(body.expires_at) if body.expires_at is not None else machine.expires_at
    enabling = body.disabled is False and machine.disabled
    # Включить машину, сменить ей адреса или срок - значит решать, откуда и до
    # какого числа ее секрет открывает окружения. Как и перевыпуск секрета,
    # это можно только тому, кто сам читает все, что она открывает.
    # Охват - с новым сроком: поставить машине срок в пределах своего права
    # можно, а тому, кто ее окружение не читает, нельзя и сократить (срок
    # "завтра" оставил бы сервер без значений, как и удаление).
    if enabling or ips != machine.allow_ips or _iso(expires) != _iso(machine.expires_at):
        await _require_reach(session, user, [machine.id], expires={machine.id: expires})
    changes: list[str] = []
    if body.name is not None and body.name.strip()[:120] != machine.name:
        machine.name = body.name.strip()[:120]
        changes.append("название")
    if body.description is not None and body.description.strip()[:300] != machine.description:
        machine.description = body.description.strip()[:300]
        changes.append("описание")
    if ips != machine.allow_ips:
        changes.append(
            f"адреса: {machine.allow_ips or 'откуда угодно'} → {ips or 'откуда угодно'}"
        )
        machine.allow_ips = ips
    if _iso(expires) != _iso(machine.expires_at):
        changes.append(
            f"срок: {_iso(machine.expires_at)[:10] or 'бессрочно'} → {_iso(expires)[:10] or 'бессрочно'}"
        )
        machine.expires_at = expires
    if changes:
        await audit.record(
            session,
            actor=user.username,
            action="machine_updated",
            target=machine.name,
            detail="; ".join(changes),
            ip=peer_ip(request),
        )
    if body.disabled is not None and body.disabled != machine.disabled:
        machine.disabled = body.disabled
        # Выключение должно действовать сразу, а не через четверть часа, когда
        # истечет уже выданный токен.
        await bump_token_version(session, machine)
        await audit.record(
            session,
            actor=user.username,
            action="machine_disabled" if body.disabled else "machine_enabled",
            target=machine.name,
            ip=peer_ip(request),
        )
    await session.commit()
    return await _out(session, machine)


class PublicKeyOut(BaseModel):
    public_key: str = ""


@router.get("/{machine_id}/public-key", response_model=PublicKeyOut)
async def public_key(
    machine_id: int, _: MaintainerUser, session: SessionDep
) -> PublicKeyOut:
    """Публичный ключ ноды: им браузер запечатывает ключ e2e-проекта.

    Секретом он не является - тем и хорош: панель может отдать его любому, кто
    и так распоряжается машинами, и ничего при этом не раскрывает.
    """
    machine = await session.get(MachineIdentity, machine_id)
    if machine is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Машина не найдена")
    return PublicKeyOut(public_key=machine.public_key)


@router.post("/{machine_id}/secret", response_model=CreatedOut)
async def rotate_secret(
    machine_id: int, request: Request, user: MaintainerUser, session: SessionDep
) -> CreatedOut:
    """Новый секрет вместо прежнего. Старый перестает работать сразу, вместе с
    уже выданными токенами."""
    machine = await session.get(MachineIdentity, machine_id)
    if machine is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Машина не найдена")
    if machine.cluster_id is not None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "У кластерной личности нет секрета: вход по токену ServiceAccount",
        )
    await _require_reach(session, user, [machine.id])
    _client_id, secret = machines.new_credentials()
    machine.secret_hash = hash_token(secret)
    await bump_token_version(session, machine)
    await audit.record(
        session,
        actor=user.username,
        action="machine_secret_rotated",
        target=machine.name,
        ip=peer_ip(request),
    )
    await session.commit()
    base = await _out(session, machine)
    return CreatedOut(**base.model_dump(), client_secret=secret)


@router.delete("/{machine_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_machine(
    machine_id: int,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
    confirm: str = Query(default="", max_length=120),
) -> None:
    machine = await session.get(MachineIdentity, machine_id)
    if machine is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Машина не найдена")
    if confirm != machine.name:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Для удаления подтвердите имя машины: {machine.name}",
        )
    # Удалить машину - оставить без значений сервер, который читает выданное
    # ей. Как и прочее с ее учетными данными, это тому, кто сам все это читает.
    await _require_reach(session, user, [machine.id])
    # Политики машины уходят вместе с ней: осиротевшее право потом достанется
    # новой личности с тем же номером.
    await session.execute(
        delete(Policy).where(Policy.subject_type == "machine", Policy.subject_id == machine.id)
    )
    name = machine.name
    await session.delete(machine)
    await audit.record(
        session,
        actor=user.username,
        action="machine_deleted",
        target=name,
        ip=peer_ip(request),
    )
    await session.commit()


class AttachIn(BaseModel):
    environment_id: int


class AttachOut(BaseModel):
    environment: str
    command: str
    granted: bool
    # Срок права машины: подключение временным ответственным дает его не
    # дольше, чем есть у него самого. Пусто - без срока.
    expires_at: str = ""


def _app_command(panel: str, project: Project, environment: Environment) -> str:
    """Команда, которую человек выполняет на сервере с уже работающим агентом.

    Одна строка и никаких флагов: пути агент выводит из имени проекта, а
    перезапускать его не нужно - список приложений он перечитывает сам.
    """
    place = f"{project.group_slug}/" if project.group_slug else ""
    return f"sudo sekvyr add {place}{project.slug}/{environment.name}"


def _install_command(
    panel: str, token: str, project: Project | None, environment: Environment | None, lang: str
) -> str:
    """Команда для сервера, которого в панели еще нет: подключение и первое
    приложение сразу, чтобы не возвращаться сюда второй раз.

    Язык интерфейса, из которого взяли команду, уходит установщику: на нем
    говорят и он сам, и агент потом, в том числе в журнале службы.
    """
    tail = f" --lang {lang}" if lang else ""
    if project is None or environment is None:
        return f"curl -fsSL {panel}/api/v1/machine/install.sh | sudo sh -s -- --token {token}{tail}"
    group = f" --group {project.group_slug}" if project.group_slug else ""
    return (
        f"curl -fsSL {panel}/api/v1/machine/install.sh | sudo sh -s -- "
        f"--token {token} --project {project.slug} --env {environment.name}{group}{tail}"
    )


@router.post("/{machine_id}/attach", response_model=AttachOut)
async def attach_environment(
    machine_id: int,
    body: AttachIn,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
) -> AttachOut:
    """Выдает машине окружение и отдает команду для этого приложения.

    Раньше это было два действия в разных разделах: политика в "Доступе" и
    команда, собранная руками из пяти флагов. Забыть первое легко, и агент
    упирался в "этой машине окружение не выдано" - так и вышло на живой
    проверке. Одно действие вместо двух, и забывать больше нечего.
    """
    machine = await session.get(MachineIdentity, machine_id)
    if machine is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Машина не найдена")
    environment = await session.get(Environment, body.environment_id)
    if environment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
    project = await session.get(Project, environment.project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Проект не найден")
    await _require_read(session, user, environment)
    # Машина получает право от имени того, кто ее подключает, и не дольше, чем
    # оно есть у него самого: временный доступ иначе переживал себя через
    # машину.
    _ok, until = await access.whole_until(
        session,
        user,
        access.READ,
        environment.project_id,
        environment.id,
        await secrets_store.env_paths(session, environment.id),
    )

    existing = await session.scalar(
        select(Policy).where(
            Policy.subject_type == "machine",
            Policy.subject_id == machine.id,
            Policy.environment_id == environment.id,
            Policy.effect == "allow",
        )
    )
    granted = existing is None
    # Право уже есть, но его срок кончился: подключение выдает его заново (не
    # дольше, чем есть у подключающего), а не отвечает "доступ уже был", пока
    # агент получает 403. Живой срок не трогаем: его мог поставить владелец
    # в "Доступе" нарочно.
    if existing is not None and existing.expires_at is not None:
        current = existing.expires_at if existing.expires_at.tzinfo else existing.expires_at.replace(tzinfo=timezone.utc)
        if current <= datetime.now(timezone.utc):
            existing.expires_at = until
            granted = True
            await audit.record(
                session,
                actor=user.username,
                action="policy_updated",
                target=f"machine:{machine.name}",
                detail=f"{project.slug}/{environment.name}: срок "
                + (until.isoformat(timespec="minutes") if until else "снят"),
                ip=peer_ip(request),
            )
            await session.commit()
    elif granted:
        # Ровно чтение: машине больше и не положено, а расширять права молча -
        # худшее, что может сделать кнопка "подключить".
        session.add(
            Policy(
                subject_type="machine",
                subject_id=machine.id,
                environment_id=environment.id,
                project_id=environment.project_id,
                path_prefix="/",
                actions="list,read",
                effect="allow",
                created_by=user.username,
                expires_at=until,
            )
        )
        await audit.record(
            session,
            actor=user.username,
            action="policy_created",
            target=f"machine:{machine.name}",
            detail=f"{project.slug}/{environment.name}: list, read"
            + (f" · до {until.isoformat(timespec='minutes')}" if until else ""),
            ip=peer_ip(request),
        )
        await session.commit()

    held = await session.scalar(
        select(Policy.expires_at).where(
            Policy.subject_type == "machine",
            Policy.subject_id == machine.id,
            Policy.environment_id == environment.id,
            Policy.effect == "allow",
        )
    )
    return AttachOut(
        environment=f"{project.slug}/{environment.name}",
        command=_app_command(get_settings().panel_url.rstrip("/"), project, environment),
        granted=granted,
        expires_at=to_utc(held).isoformat() if held else "",
    )


class EnrollTokenIn(BaseModel):
    """Что выдать серверу сразу после подключения."""

    environment_id: int | None = None
    allow_ips: str = Field(default="", max_length=500)
    minutes: int = Field(default=15, ge=1, le=1440)
    # Язык интерфейса: на нем будут говорить установщик и агент.
    lang: str = Field(default="", pattern=r"^(ru|en)?$")


class EnrollTokenOut(BaseModel):
    token: str
    expires_at: str
    environment: str = ""
    command: str
    # Команда для сервера, который уже подключен: ставит агента ЭТОМУ
    # приложению, не расходуя токен. Без нее человек собирает четыре флага
    # руками и ошибается в группе - так и было на первой живой проверке.
    app_command: str = ""


@router.post("/enroll-token", response_model=EnrollTokenOut)
async def create_enroll_token(
    body: EnrollTokenIn, request: Request, user: MaintainerUser, session: SessionDep
) -> EnrollTokenOut:
    """Одноразовый токен подключения сервера и готовая команда установки.

    Срок по умолчанию четверть часа: токен действует ровно столько, сколько идет
    подключение, и не остается лежать в переписке.
    """
    environment = None
    if body.environment_id is not None:
        environment = await session.get(Environment, body.environment_id)
        if environment is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
        # Сервер, подключенный по токену, сразу читает это окружение.
        await _require_read(session, user, environment)

    raw = generate_token()
    expires = datetime.now(timezone.utc) + timedelta(minutes=body.minutes)
    session.add(
        EnrollToken(
            token_hash=hash_token(raw),
            environment_id=environment.id if environment else None,
            # Те же правила, что у адресов машины: адрес с опечаткой ушел бы в
            # личность как есть и молча не пускал сервер ни разу.
            allow_ips=_ips(body.allow_ips),
            expires_at=expires,
            created_by=user.username,
        )
    )
    await audit.record(
        session,
        actor=user.username,
        action="enroll_token_created",
        target=f"{environment.name}" if environment else "",
        detail=f"на {body.minutes} мин",
        ip=peer_ip(request),
    )
    await session.commit()

    panel = get_settings().panel_url or str(request.base_url).rstrip("/")
    project = (
        await session.get(Project, environment.project_id) if environment else None
    )
    command = _install_command(panel, raw, project, environment, body.lang)
    app_command = _app_command(panel, project, environment) if project and environment else ""
    return EnrollTokenOut(
        token=raw,
        expires_at=expires.isoformat(),
        environment=f"{project.slug}/{environment.name}" if project and environment else "",
        command=command,
        app_command=app_command,
    )


# --- кластеры ---------------------------------------------------------------


class ClusterIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    # `iss` из токена: у managed-кластеров URL, у ванильных kubernetes/serviceaccount
    issuer: str = Field(min_length=1, max_length=300)
    audience: str = Field(default="sekvyr", min_length=1, max_length=120)
    # kubectl get --raw /openid/v1/jwks
    jwks: str = Field(min_length=2, max_length=20000)


class ClusterOut(BaseModel):
    id: int
    name: str
    issuer: str
    audience: str
    disabled: bool = False
    # Сколько личностей за этим кластером: по нему видно, что запись живая.
    identities: int = 0


@router.get("/clusters", response_model=list[ClusterOut])
async def list_clusters(user: MaintainerUser, session: SessionDep) -> list[ClusterOut]:
    out: list[ClusterOut] = []
    for cluster in await session.scalars(select(Cluster).order_by(Cluster.name)):
        count = len(
            list(
                await session.scalars(
                    select(MachineIdentity).where(MachineIdentity.cluster_id == cluster.id)
                )
            )
        )
        out.append(
            ClusterOut(
                id=cluster.id,
                name=cluster.name,
                issuer=cluster.issuer,
                audience=cluster.audience,
                disabled=cluster.disabled,
                identities=count,
            )
        )
    return out


@router.post("/clusters", response_model=ClusterOut, status_code=status.HTTP_201_CREATED)
async def create_cluster(
    body: ClusterIn, request: Request, user: MaintainerUser, session: SessionDep
) -> ClusterOut:
    """Кластер, чьим ServiceAccount-токенам панель верит.

    Ключи проверяются здесь же: запись с нечитаемым JWKS выглядела бы рабочей до
    первого пода, а разбираться в этом пришлось бы в кластере, а не в панели.
    """
    try:
        kube.load_keys(body.jwks)
    except kube.TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    cluster = Cluster(
        name=body.name.strip(),
        issuer=body.issuer.strip(),
        audience=body.audience.strip(),
        jwks=body.jwks,
        created_by=user.username,
    )
    session.add(cluster)
    await session.flush()
    await audit.record(
        session,
        actor=user.username,
        action="cluster_added",
        target=cluster.name,
        detail=cluster.issuer,
        ip=peer_ip(request),
    )
    await session.commit()
    return ClusterOut(
        id=cluster.id,
        name=cluster.name,
        issuer=cluster.issuer,
        audience=cluster.audience,
    )


class ClusterKeysIn(BaseModel):
    """Новые ключи кластера. Пустые issuer и audience оставляют прежние."""

    issuer: str = Field(default="", max_length=300)
    audience: str = Field(default="", max_length=120)
    jwks: str = Field(min_length=2, max_length=20000)


@router.patch("/clusters/{cluster_id}", response_model=ClusterOut)
async def update_cluster(
    cluster_id: int,
    body: ClusterKeysIn,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
) -> ClusterOut:
    """Новые ключи кластера на месте.

    Кластер меняет ключи подписи редко, но после смены токены его подов
    перестают проходить. Раньше запись можно было только удалить и завести
    заново, а вместе с ней уходили личности подов и выданные им права.
    """
    cluster = await session.get(Cluster, cluster_id)
    if cluster is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Кластер не найден")
    # Своими ключами можно выписывать токены подам этого кластера: менять их
    # может только тот, кто читает все, что эти поды.
    await _require_reach(
        session,
        user,
        list(
            await session.scalars(
                select(MachineIdentity.id).where(MachineIdentity.cluster_id == cluster.id)
            )
        ),
    )
    try:
        kube.load_keys(body.jwks)
    except kube.TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    changes = ["ключи"]
    if body.issuer.strip() and body.issuer.strip() != cluster.issuer:
        cluster.issuer = body.issuer.strip()
        changes.append(f"issuer {cluster.issuer}")
    if body.audience.strip() and body.audience.strip() != cluster.audience:
        cluster.audience = body.audience.strip()
        changes.append(f"audience {cluster.audience}")
    cluster.jwks = body.jwks
    await audit.record(
        session,
        actor=user.username,
        action="cluster_updated",
        target=cluster.name,
        detail="; ".join(changes),
        ip=peer_ip(request),
    )
    await session.commit()
    identities = len(
        list(
            await session.scalars(
                select(MachineIdentity.id).where(MachineIdentity.cluster_id == cluster.id)
            )
        )
    )
    return ClusterOut(
        id=cluster.id,
        name=cluster.name,
        issuer=cluster.issuer,
        audience=cluster.audience,
        disabled=cluster.disabled,
        identities=identities,
    )


@router.delete("/clusters/{cluster_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cluster(
    cluster_id: int,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
    confirm: str = Query(default="", max_length=120),
) -> None:
    cluster = await session.get(Cluster, cluster_id)
    if cluster is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Кластер не найден")
    if confirm != cluster.name:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Для удаления подтвердите имя кластера: {cluster.name}",
        )
    await _require_reach(
        session,
        user,
        list(
            await session.scalars(
                select(MachineIdentity.id).where(MachineIdentity.cluster_id == cluster.id)
            )
        ),
    )
    name = cluster.name
    # Личности этого кластера уходят вместе с ним: без ключей проверять их
    # токены нечем, а "личность, которая никогда не войдет" - это мусор.
    #
    # Удаляем явно, а не каскадом базы. У права нет внешнего ключа на личность,
    # и каскад оставлял права висеть на номере удаленной личности - номер потом
    # достается новой машине вместе с чужим доступом. А в SQLite каскада нет
    # вовсе: личности оставались с номером несуществующего кластера.
    identities = list(
        await session.scalars(
            select(MachineIdentity.id).where(MachineIdentity.cluster_id == cluster.id)
        )
    )
    revoked = 0
    if identities:
        result = await session.execute(
            delete(Policy).where(
                Policy.subject_type == "machine", Policy.subject_id.in_(identities)
            )
        )
        revoked = result.rowcount or 0
        await session.execute(delete(MachineApp).where(MachineApp.machine_id.in_(identities)))
        await session.execute(delete(MachineIdentity).where(MachineIdentity.id.in_(identities)))
    await session.delete(cluster)
    await audit.record(
        session,
        actor=user.username,
        action="cluster_removed",
        target=name,
        detail=f"личностей {len(identities)}, прав снято {revoked}" if identities else "",
        ip=peer_ip(request),
    )
    await session.commit()
