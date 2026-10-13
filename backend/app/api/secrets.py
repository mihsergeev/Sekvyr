"""Секреты: список, значения, запись, удаление, история, снимки, обмен .env.

Право на каждое действие проверяется политиками (app/access.py), а не ролью:
роль решает, кто кем командует, а доступ к конкретному окружению и пути живет
отдельно. Разделение `list` и `read` - тот самый случай, ради которого действия
и разделены: разработчику надо знать, какие переменные нужны приложению, а не
что в них лежит.

Правка от роли ниже порога проекта не вступает в силу сразу: она ложится
ожидающей версией, приложения продолжают получать прежнее значение, а
подтверждает её тот, кто выше автора.

Каждое чтение значения попадает в журнал. Не "страница открыта", а "прочитан
такой-то ключ" - это единственный способ потом ответить на вопрос, кто видел
прод-пароль до того, как он утек.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app import access, alerts, audit, crypto, lint, roles, secrets_store
from app.audit import to_utc
from app.config import get_settings
from app.deps import BoxDep, CurrentUser, MaintainerUser, SessionDep, UnsealedBox, peer_ip
from app.models import (
    AuditLog,
    Environment,
    EnvSnapshot,
    Group,
    LintMute,
    MachineIdentity,
    Policy,
    Project,
    User,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/environments/{env_id}", tags=["secrets"])


def _iso(moment) -> str:
    """Время в ISO с зоной. Без зоны браузер считает его местным, и правка
    часовой давности уезжает на несколько часов. `to_utc` уже умеет обе формы:
    Postgres отдает метку с зоной, SQLite - без нее."""
    return to_utc(moment).isoformat() if moment else ""


class SecretOut(BaseModel):
    """Ключ БЕЗ значения. Отдельная модель именно для того, чтобы значение
    физически не могло попасть в список: одно поле - одна возможность ошибиться."""

    name: str
    path: str
    version: int
    updated_by: str = ""
    # Когда значение меняли последний раз. В списке это единственная цифра, по
    # которой видно живой ключ и забытый: имя и звездочки об этом не говорят
    # ничего.
    updated_at: str = ""

    # Есть ли по этому ключу правка, ждущая подтверждения. Показывается в списке,
    # чтобы "я же поменял" не превращалось в спор с приложением.
    pending: bool = False
    # Имя окружения, из которого пришло значение, если оно не свое. Пусто -
    # значит задано здесь. Без этого невозможно понять, почему правка в tech1
    # "не сработала": она и не должна была, ключ живет в родителе.
    inherited_from: str = ""
    # Многострочное значение: конфиг или ключ, а не пароль в одну строку. В
    # списке они выглядели одинаково, а открывают их по-разному.
    multiline: bool = False
    # Зачем ключ нужен и к какой дате значение надо заменить.
    note: str = ""
    expires_at: str = ""
    # Окружения, где ключ переименовали заодно. Пусто - переименовали только
    # здесь.
    also_renamed: list[str] = []


class ValueRow(BaseModel):
    """Значение в списке: то же, что в ValueOut, плюс откуда оно пришло."""

    name: str
    path: str
    version: int
    value: str
    inherited_from: str = ""


class ValueOut(BaseModel):
    name: str
    path: str
    version: int
    value: str


class SecretIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(default="/", max_length=200)
    value: str = Field(max_length=200_000)
    comment: str = Field(default="", max_length=500)


class RotateOut(BaseModel):
    key_generation: int
    reencrypted_versions: int


async def _env(session: SessionDep, env_id: int) -> Environment:
    env = await session.get(Environment, env_id)
    if env is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
    return env


async def _guard(
    session: SessionDep, user, env_id: int, action: str, path: str = "/"
) -> Environment:
    """Окружение плюс проверка права на действие именно в этом месте.

    Одна функция на все маршруты: проверку легко забыть, когда она пишется
    заново в каждом обработчике, а "забыли проверку" здесь означает выданный
    чужой пароль.
    """
    env = await _env(session, env_id)
    await access.require(
        session,
        user,
        action,
        access.Scope(project_id=env.project_id, environment_id=env.id, path=path),
    )
    return env


async def _guard_any(session: SessionDep, user, env_id: int, action: str) -> Environment:
    """Окружение, где у человека есть право хоть на одну папку. Списки потом
    фильтруются по каждому пути: проверка по корню не пускала тех, у кого
    право только на /app, и пускала тех, у кого запрет на /private."""
    env = await _env(session, env_id)
    visible = await access.visible_in(session, user, action, env.project_id, [env.id])
    if env.id not in visible:
        await access.require(
            session, user, action, access.Scope(project_id=env.project_id, environment_id=env.id, path="/")
        )
    return env


async def _guard_whole(session: SessionDep, user, env_id: int, action: str) -> Environment:
    """Окружение, где у человека есть право на каждую папку. Нужно тому, что
    выносит или меняет окружение целиком: выгрузке, всем значениям, снимку.
    Раньше право спрашивалось на корень, и запрет на /private обходился
    выгрузкой."""
    env = await _env(session, env_id)
    paths = await secrets_store.env_paths(session, env_id)
    if not await access.covers_whole(session, user, action, env.project_id, env.id, paths):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f'В окружении есть папки, где у вас нет права "{access.TITLES.get(action, action)}": '
            "действие над всем окружением недоступно",
        )
    return env


async def _checker(session: SessionDep, user, env: Environment, action: str) -> access.PlaceCheck:
    return await access.place_check(session, user, action, env.project_id, env.id)


async def _needs_approval(session: SessionDep, user, env: Environment) -> bool:
    """Требует ли правка подтверждения.

    Порог задается на проект и сравнивается с уровнем роли: кто в проекте
    главный, тот правит сразу, у остальных изменение ждет того, кто выше.
    """
    project = await session.get(Project, env.project_id)
    threshold = project.approval_min_level if project else 0
    return bool(threshold) and roles.level(user.role) < threshold


DIRECT_ONLY = (
    "Правки вашей роли в этом проекте идут на подтверждение, а это действие его "
    "не проходит: оно доступно роли не ниже порога проекта"
)


async def refuse_below_threshold(session: SessionDep, user, env: Environment) -> None:
    """Удаление, переименование, импорт, перенос, возврат к наследованию и
    восстановление снимка не умеют ждать подтверждения. Ниже порога они
    выпускали бы изменение в обход него, поэтому там им отказ: значения роль
    ниже порога меняет сохранением и откатом, а их подтверждают."""
    if await _needs_approval(session, user, env):
        raise HTTPException(status.HTTP_403_FORBIDDEN, DIRECT_ONLY)


@router.get("/secrets", response_model=list[SecretOut])
async def list_secrets(
    env_id: int, user: CurrentUser, session: SessionDep
) -> list[SecretOut]:
    env = await _guard_any(session, user, env_id, access.LIST)
    can_list = await _checker(session, user, env, access.LIST)
    rows = [
        (secret, level)
        for secret, level in await secrets_store.effective_list(session, env_id)
        if can_list(secret.path)
    ]
    waiting = {
        (secret.path, secret.name)
        for secret, _version in await secrets_store.pending_versions(session, env_id)
    }
    names: dict[int, str] = {}
    out: list[SecretOut] = []
    # Версии одним запросом на весь список: маршрут повторял работу, которую
    # `effective_list` только что сделал, - и делал её снова по строке.
    versions = await secrets_store.current_versions(
        session, [secret.id for secret, _ in rows]
    )
    for secret, level in rows:
        version = versions.get(secret.id)
        if level != env_id and level not in names:
            parent = await session.get(Environment, level)
            names[level] = parent.name if parent else str(level)
        out.append(
            SecretOut(
                name=secret.name,
                path=secret.path,
                version=secret.current_version,
                updated_by=version.author if version else "",
                updated_at=_iso(version.created_at) if version else "",
                multiline=bool(version.multiline) if version else False,
                note=secret.note,
                expires_at=_iso(secret.expires_at),
                pending=(secret.path, secret.name) in waiting,
                inherited_from="" if level == env_id else names[level],
            )
        )
    return out


@router.get("/secret", response_model=ValueOut)
async def read_secret(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
    name: str = Query(min_length=1, max_length=200),
    path: str = Query(default="/", max_length=200),
) -> ValueOut:
    await _guard(session, user, env_id, access.READ, path)
    # Ищем по цепочке наследования: право спрашивается на ТО окружение, которое
    # человек открыл. Доступ к tech1 означает доступ и к значениям его родителя -
    # иначе наследование было бы бесполезным: приложение на tech1 получает ровно
    # эти значения.
    found = await secrets_store.resolve(session, env_id, path, name)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Такого ключа здесь нет")
    secret, _level = found
    try:
        value = await secrets_store.read_value(session, box, secret)
    except crypto.DecryptionError as exc:
        # Значение не расшифровалось при живом ключе - либо база правлена мимо
        # панели, либо оборвалась ротация. Молчать нельзя: это состояние, о
        # котором должен узнать человек, а не пустой ответ.
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Значение не сошлось с ключом — возможна правка базы в обход панели",
        ) from exc

    await audit.record(
        session,
        actor=user.username,
        action="secret_read",
        target=f"{env_id}:{secret.path}:{secret.name}",
        detail=f"версия {secret.current_version}",
        ip=peer_ip(request),
    )
    await session.commit()
    return ValueOut(
        name=secret.name, path=secret.path, version=secret.current_version, value=value
    )


async def _tell_about_prod(
    session: SessionDep, env: Environment, user, names: list[str], what: str
) -> None:
    """Сообщить, что боевое окружение тронули.

    Одно сообщение на операцию, а не на ключ: импорт сорока переменных должен
    читаться как одна новость, иначе канал оповещений выключат вместе со всем
    остальным, что панель в него пишет.
    """
    watched = get_settings().alert_on_envs.split()
    if not watched or env.name not in watched or not names:
        return
    project = await session.get(Project, env.project_id)
    where = f"{project.slug}/{env.name}" if project else env.name
    shown = ", ".join(names[:10]) + (f" …и ещё {len(names) - 10}" if len(names) > 10 else "")
    await alerts.notify(session, f"✏️ Sekvyr: {user.username} {what} в {where} — {shown}")


@router.put("/secrets", response_model=SecretOut)
async def put_secret(
    env_id: int,
    body: SecretIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> SecretOut:
    env = await _guard(session, user, env_id, access.WRITE, body.path)
    pending = await _needs_approval(session, user, env)
    try:
        version = await secrets_store.set_value(
            session,
            box,
            env_id=env_id,
            path=body.path,
            name=body.name,
            value=body.value,
            author=user.username,
            comment=body.comment,
            pending=pending,
        )
    except secrets_store.SealedValueRequired as exc:
        # В проекте с шифрованием в браузере значение должно приходить
        # запечатанным: открытый текст сюда попадает только по ошибке клиента.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await audit.record(
        session,
        actor=user.username,
        action="secret_pending" if pending else "secret_written",
        target=f"{env_id}:{version.path_at}:{version.name_at}",
        # В журнал уходит НОМЕР версии, а не значение и даже не его длина:
        # длина пароля - это подсказка тому, кто будет его подбирать.
        detail=f"версия {version.version}",
        ip=peer_ip(request),
    )
    await _tell_about_prod(
        session,
        env,
        user,
        [version.name_at],
        "отправил на подтверждение правку" if pending else "поменял значение",
    )
    await session.commit()
    return SecretOut(
        name=version.name_at,
        path=version.path_at,
        version=version.version,
        updated_by=user.username,
        pending=pending,
    )


@router.delete("/secret", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
    name: str = Query(min_length=1, max_length=200),
    path: str = Query(default="/", max_length=200),
) -> None:
    env = await _guard(session, user, env_id, access.DELETE, path)
    await refuse_below_threshold(session, user, env)
    secret = await secrets_store.get_secret(session, env_id, path, name)
    if secret is None or secret.deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Такого ключа здесь нет")
    version = await secrets_store.delete_secret(
        session, box, secret, author=user.username
    )
    await audit.record(
        session,
        actor=user.username,
        action="secret_deleted",
        target=f"{env_id}:{secret.path}:{secret.name}",
        detail=f"версия {version.version}",
        ip=peer_ip(request),
    )
    await _tell_about_prod(session, env, user, [secret.name], "удалил ключ")
    await session.commit()


@router.post("/rotate-key", response_model=RotateOut)
async def rotate_key(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> RotateOut:
    """Сменить ключ окружения и перешифровать все, что им зашифровано."""
    await _guard(session, user, env_id, access.ROTATE)
    generation, count = await secrets_store.rotate_env_key(session, box, env_id)
    await audit.record(
        session,
        actor=user.username,
        action="env_key_rotated",
        target=str(env_id),
        detail=f"поколение {generation}, перешифровано версий: {count}",
        ip=peer_ip(request),
    )
    await session.commit()
    return RotateOut(key_generation=generation, reencrypted_versions=count)


# --- история и откат -------------------------------------------------------


class VersionOut(BaseModel):
    """Версия БЕЗ значения: список версий может смотреть тот, кому нельзя
    читать содержимое."""

    version: int
    name: str
    path: str
    deleted: bool
    author: str
    comment: str
    created_at: str
    current: bool
    # current, superseded, pending или rejected: откатиться можно только к
    # версии, которая действовала, и интерфейс не предлагает остальное.
    status: str = ""
    # Значение версии лежало в папке, где у человека нет права читать (ключ
    # потом перенесли): раскрыть и вернуть ее он не сможет, и интерфейс это
    # знает заранее, а не по отказу.
    closed: bool = False
    # "брать у родителя": своего значения у такой версии нет.
    inherits: bool = False


class RollbackIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(default="/", max_length=200)
    version: int = Field(ge=1)


class RenameIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(default="/", max_length=200)
    new_name: str = Field(min_length=1, max_length=200)
    new_path: str = Field(default="/", max_length=200)
    # Переименовать и в остальных окружениях проекта: имя ключа - общий словарь,
    # и расхождение между стендами находят на выкате.
    everywhere: bool = False


MAX_IMPORT_KEYS = 5000


class ImportIn(BaseModel):
    text: str = Field(max_length=1_000_000)
    path: str = Field(default="/", max_length=200)
    # По умолчанию НЕ перезаписываем: залить чужой .env поверх рабочего
    # окружения - самый простой способ тихо испортить прод.
    overwrite: bool = False


class ImportOut(BaseModel):
    created: int
    updated: int
    skipped: list[str]


class ExportOut(BaseModel):
    text: str


class SnapshotOut(BaseModel):
    id: int
    name: str
    author: str
    created_at: str
    keys: int


class SnapshotIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class PlanRow(BaseModel):
    path: str
    name: str
    action: str


class RestoreOut(BaseModel):
    restored: int
    removed: int


async def _secret_or_404(session, env_id: int, path: str, name: str):
    secret = await secrets_store.get_secret(session, env_id, path, name)
    if secret is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Такого ключа здесь нет")
    return secret


@router.get("/secret/history", response_model=list[VersionOut])
async def secret_history(
    env_id: int,
    user: CurrentUser,
    session: SessionDep,
    name: str = Query(min_length=1, max_length=200),
    path: str = Query(default="/", max_length=200),
) -> list[VersionOut]:
    env = await _guard(session, user, env_id, access.LIST, path)
    secret = await _secret_or_404(session, env_id, path, name)
    rows = await secrets_store.history(session, secret)
    # Ключ мог приехать переименованием из папки, которой человек не видит:
    # прежние имя и папка в истории - сведения о ней.
    can_list = await _checker(session, user, env, access.LIST)
    can_read = await _checker(session, user, env, access.READ)
    return [
        VersionOut(
            closed=bool(v.path_at) and v.path_at != secret.path and not can_read(v.path_at),
            version=v.version,
            name=v.name_at if can_list(v.path_at or "/") else secret.name,
            path=v.path_at if can_list(v.path_at or "/") else secret.path,
            deleted=v.deleted,
            author=v.author,
            comment=_hide_closed_place(v.comment or "", can_list),
            created_at=to_utc(v.created_at).isoformat() if v.created_at else "",
            current=v.version == secret.current_version,
            status=v.status,
            inherits=v.inherits,
        )
        for v in rows
    ]


async def _guard_version_place(session: SessionDep, user, env: Environment, secret, version_no: int) -> None:
    """Версия, записанная, пока ключ лежал в другой папке, - значение той
    папки. Ключ перенесли из /private в корень, и старое значение читалось
    (и откатывалось) по номеру версии тем, кому /private закрыта."""
    version = await secrets_store.get_version(session, secret, version_no)
    if version is not None and version.path_at and version.path_at != secret.path:
        await access.require(
            session,
            user,
            access.READ,
            access.Scope(project_id=env.project_id, environment_id=env.id, path=version.path_at),
        )


@router.get("/secret/version", response_model=ValueOut)
async def secret_version_value(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
    name: str = Query(min_length=1, max_length=200),
    path: str = Query(default="/", max_length=200),
    version: int = Query(ge=1),
) -> ValueOut:
    """Значение старой версии. Право то же, что на текущее: кто не видит
    сегодняшний пароль, не увидит и вчерашний."""
    env = await _guard(session, user, env_id, access.READ, path)
    secret = await _secret_or_404(session, env_id, path, name)
    await _guard_version_place(session, user, env, secret, version)
    try:
        value = await secrets_store.read_version(session, box, secret, version)
    except secrets_store.SecretNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except crypto.DecryptionError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Значение не сошлось с ключом — возможна правка базы в обход панели",
        ) from exc
    await audit.record(
        session,
        actor=user.username,
        action="secret_version_read",
        target=f"{env_id}:{secret.path}:{secret.name}",
        detail=f"версия {version}",
        ip=peer_ip(request),
    )
    await session.commit()
    return ValueOut(name=secret.name, path=secret.path, version=version, value=value)


@router.post("/secret/rollback", response_model=SecretOut)
async def secret_rollback(
    env_id: int,
    body: RollbackIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> SecretOut:
    env = await _guard(session, user, env_id, access.WRITE, body.path)
    secret = await _secret_or_404(session, env_id, body.path, body.name)
    await _guard_version_place(session, user, env, secret, body.version)
    pending = await _needs_approval(session, user, env)
    try:
        version = await secrets_store.rollback(
            session,
            box,
            secret,
            body.version,
            author=user.username,
            pending=pending,
        )
    except secrets_store.SecretNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    # Откат ниже порога - такое же предложение, как обычная правка: журнал,
    # оповещение и ответ говорят "на подтверждении", а не "стала версия", -
    # значение на деле не менялось.
    await audit.record(
        session,
        actor=user.username,
        action="secret_pending" if pending else "secret_rolled_back",
        target=f"{env_id}:{secret.path}:{secret.name}",
        detail=(
            f"откат к версии {body.version}, на подтверждении версия {version.version}"
            if pending
            else f"к версии {body.version}, стала версия {version.version}"
        ),
        ip=peer_ip(request),
    )
    await _tell_about_prod(
        session,
        env,
        user,
        [secret.name],
        "отправил на подтверждение откат" if pending else "вернул прежнее значение",
    )
    await session.commit()
    return SecretOut(
        name=version.name_at,
        path=version.path_at,
        version=version.version,
        updated_by=user.username,
        pending=pending,
    )


class MetaIn(BaseModel):
    """Подпись ключа и срок замены значения. Пустая строка стирает."""

    path: str = "/"
    name: str
    note: str = Field(default="", max_length=200)
    # Дата в ISO ("2027-03-01") или пусто. Время не спрашиваем: срок токена -
    # это про день, а не про час.
    expires_at: str = Field(default="", max_length=40)


@router.post("/secret/meta", response_model=SecretOut)
async def secret_meta(
    env_id: int,
    body: MetaIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> SecretOut:
    """Задать подпись ключа и дату, к которой значение надо заменить.

    Значения это не касается вовсе: ни новой версии, ни подтверждения здесь не
    появляется. Право нужно то же, что на правку, - подпись видят все, кто
    открывает окружение, и менять её мимоходом не стоит.
    """
    await _guard(session, user, env_id, access.WRITE, body.path)
    secret = await _secret_or_404(session, env_id, body.path, body.name)

    when: datetime | None = None
    if body.expires_at.strip():
        # Сразу в UTC (как у прав и машин); крайняя дата со смещением - ошибка
        # даты, а не "номер вне диапазона".
        try:
            when = datetime.fromisoformat(body.expires_at.strip())
            when = when.replace(tzinfo=timezone.utc) if when.tzinfo is None else when.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Не разобрал дату: нужен вид 2027-03-01"
            ) from None

    secret.note = body.note.strip()[:200]
    secret.expires_at = when
    await audit.record(
        session,
        actor=user.username,
        action="secret_meta",
        target=f"{env_id}:{secret.path}:{secret.name}",
        detail=(
            f"подпись: {secret.note or 'нет'}"
            + (f" · срок: {when.date().isoformat()}" if when else " · срока нет")
        ),
        ip=peer_ip(request),
    )
    await session.commit()

    version = await secrets_store.current_version(session, secret)
    return SecretOut(
        name=secret.name,
        path=secret.path,
        version=secret.current_version,
        updated_by=version.author if version else "",
        updated_at=_iso(version.created_at) if version else "",
        multiline=bool(version.multiline) if version else False,
        note=secret.note,
        expires_at=_iso(secret.expires_at),
    )


@router.post("/secret/rename", response_model=SecretOut)
async def secret_rename(
    env_id: int,
    body: RenameIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> SecretOut:
    """Переименование - новая версия с перешифровкой: имя входит в связанные
    данные шифра, и правкой строки его менять нельзя."""
    env = await _guard(session, user, env_id, access.WRITE, body.path)
    await refuse_below_threshold(session, user, env)
    # Переименование переносит значение: из папки, которую человек не читает,
    # в папку, которую читает, - это чтение в обход запрета. Поэтому нужно и
    # читать исходное место, и писать в новое.
    await access.require(
        session, user, access.READ,
        access.Scope(project_id=env.project_id, environment_id=env_id, path=body.path),
    )
    await access.require(
        session,
        user,
        access.WRITE,
        access.Scope(project_id=env.project_id, environment_id=env_id, path=body.new_path),
    )
    secret = await _secret_or_404(session, env_id, body.path, body.name)
    # Прежнее место - в каноническом виде: сырой путь из запроса ("private"
    # без слеша) прятать в ленте событий было не по чему.
    was = f"{secret.path}:{secret.name}"
    place = (secret.path, secret.name)
    if body.everywhere:
        # Окружения блокируются заранее и по возрастанию номера: так две
        # операции над несколькими окружениями не ждут друг друга по кругу.
        project_id = (await _env(session, env_id)).project_id
        for neighbour_id in sorted(
            await session.scalars(select(Environment.id).where(Environment.project_id == project_id))
        ):
            await secrets_store.lock_env(session, neighbour_id)
        # Блокировка перечитала ключ, и lock_secret внутри rename сравнил бы
        # уже свежее место с самим собой: переезд в закрытую папку, случившийся,
        # пока запрос ждал, проходил бы незамеченным.
        if (secret.path, secret.name) != place:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "ключ переименовали или перенесли, пока выполнялся запрос: обновите страницу",
            )
    try:
        version = await secrets_store.rename(
            session,
            box,
            secret,
            new_name=body.new_name,
            new_path=body.new_path,
            author=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await audit.record(
        session,
        actor=user.username,
        action="secret_renamed",
        target=f"{env_id}:{version.path_at}:{version.name_at}",
        detail=f"было {was}",
        ip=peer_ip(request),
    )

    # Остальные стенды проекта: только там, где ключ есть и куда пускают права.
    # Окружение без права пропускаем молча - отказ целиком означал бы, что общее
    # имя нельзя починить из-за одного чужого стенда.
    renamed_elsewhere: list[str] = []
    if body.everywhere:
        env = await _env(session, env_id)
        neighbours = await session.scalars(
            select(Environment)
            .where(Environment.project_id == env.project_id, Environment.id != env_id)
            .order_by(Environment.id)
        )
        for neighbour in neighbours:
            twin = await secrets_store.get_secret(session, neighbour.id, body.path, body.name)
            if twin is None:
                continue
            # В каждом окружении те же три права, что и здесь: писать и читать
            # старое место, писать новое. Раньше проверялось только новое, и
            # "везде" уносило чужой ключ из закрытой папки соседа.
            needed = (
                (access.WRITE, body.path),
                (access.READ, body.path),
                (access.WRITE, body.new_path),
            )
            permitted = True
            for action, place in needed:
                scope = access.Scope(
                    project_id=neighbour.project_id, environment_id=neighbour.id, path=place
                )
                if not await access.allowed(session, user, action, scope):
                    permitted = False
                    break
            if not permitted:
                continue
            try:
                twin_version = await secrets_store.rename(
                    session,
                    box,
                    twin,
                    new_name=body.new_name,
                    new_path=body.new_path,
                    author=user.username,
                )
            except (ValueError, secrets_store.SecretNotFound):
                # Там уже есть ключ с таким именем, или своего значения у ключа
                # там нет (удален, взят у родителя): рушить из-за этого всю
                # операцию не стоит, а в ответе его просто не будет.
                continue
            await audit.record(
                session,
                actor=user.username,
                action="secret_renamed",
                target=f"{neighbour.id}:{twin_version.path_at}:{twin_version.name_at}",
                detail=f"было {was} · вслед за {env.name}",
                ip=peer_ip(request),
            )
            renamed_elsewhere.append(neighbour.name)

    await session.commit()
    return SecretOut(
        name=version.name_at,
        path=version.path_at,
        version=version.version,
        updated_by=user.username,
        also_renamed=renamed_elsewhere,
    )


# --- обмен с .env ----------------------------------------------------------


@router.get("/export", response_model=ExportOut)
async def export_env(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> ExportOut:
    """Выгрузка всего окружения. Единственная операция, которая выносит наружу
    сразу все значения, поэтому право нужно на каждую папку окружения, а в
    журнале она стоит отдельной строкой."""
    await _guard_whole(session, user, env_id, access.READ)
    try:
        text = await secrets_store.export_env(session, box, env_id)
    except secrets_store.SealedValueRequired as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await audit.record(
        session,
        actor=user.username,
        action="env_exported",
        target=str(env_id),
        detail=f"ключей: {len(await secrets_store.list_secrets(session, env_id))}",
        ip=peer_ip(request),
    )
    await session.commit()
    return ExportOut(text=text)


class NoteOut(BaseModel):
    path: str
    name: str
    code: str
    level: str
    text: str


class MuteIn(BaseModel):
    path: str = "/"
    name: str
    code: str


@router.get("/lint", response_model=list[NoteOut])
async def check_values(
    env_id: int,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> list[NoteOut]:
    """Замечания к значениям окружения: пробел на конце, заготовка вместо
    значения, отладка на боевом стенде.

    Значения наружу не выходят - панель получает только сами замечания. Право
    все равно спрашивается на чтение: чтобы их посчитать, значения приходится
    расшифровать, и человек без права читать не должен узнавать о них даже
    столько.

    В журнал не пишем: это не чтение значений человеком, а служебная проверка,
    и запись о ней на каждое открытие страницы засорила бы журнал ровно тем,
    ради чего его не заводят.
    """
    environment = await _guard_any(session, user, env_id, access.READ)
    can_read = await _checker(session, user, environment, access.READ)

    # Принятые замечания сюда не попадают: человек уже сказал про них "так и
    # надо", и повторять - значит приучать пролистывать остальные.
    muted = {
        (row.path, row.name, row.code)
        for row in await session.scalars(
            select(LintMute).where(LintMute.environment_id == env_id)
        )
    }

    out: list[NoteOut] = []
    readable = [
        secret
        for secret, _level in await secrets_store.effective_list(session, env_id)
        if can_read(secret.path)
    ]
    plain = await secrets_store.values_of(session, box, env_id, only={secret.id for secret in readable})
    for secret in readable:
        value = plain.get((secret.path, secret.name))
        if value is None:
            continue
        for note in lint.inspect(secret.name, secret.path, value, environment.name):
            if (note.path, note.name, note.code) in muted:
                continue
            out.append(
                NoteOut(
                    path=note.path,
                    name=note.name,
                    code=note.code,
                    level=note.level,
                    text=note.text,
                )
            )
    return out


class MissingOut(BaseModel):
    path: str
    name: str
    # Где этот ключ есть: имена соседних окружений того же проекта.
    present_in: list[str]


@router.get("/missing", response_model=list[MissingOut])
async def missing_keys(
    env_id: int,
    user: CurrentUser,
    session: SessionDep,
) -> list[MissingOut]:
    """Ключи, которых здесь нет, а в соседних окружениях проекта есть.

    Отвечает на аварию, которую иначе находят на выкате: ключ добавили в stage,
    на прод забыли. Наследование учитывается само - сравниваются не "свои"
    ключи, а те, что окружение реально отдает.

    Значения не читаются вовсе: сравниваются только имена. Поэтому хватает
    права видеть ключи, а соседние окружения берутся лишь те, которые человеку
    и так видны, - иначе список рассказывал бы о чужих ключах.
    """
    environment = await _guard_any(session, user, env_id, access.LIST)
    list_here = await _checker(session, user, environment, access.LIST)

    here = {
        (secret.path, secret.name)
        for secret, _level in await secrets_store.effective_list(session, env_id)
    }

    found: dict[tuple[str, str], list[str]] = {}
    neighbours = await session.scalars(
        select(Environment).where(
            Environment.project_id == environment.project_id,
            Environment.id != env_id,
        )
    )
    for neighbour in neighbours:
        # Имя чужого ключа - только из папки, которую человек видит и там, и
        # здесь: запрет на папку скрывал бы имена в одном месте и показывал в
        # другом.
        list_there = await _checker(session, user, neighbour, access.LIST)
        for secret, _level in await secrets_store.effective_list(session, neighbour.id):
            place = (secret.path, secret.name)
            if place in here or not list_there(secret.path) or not list_here(secret.path):
                continue
            found.setdefault(place, []).append(neighbour.name)

    return [
        MissingOut(path=path, name=name, present_in=sorted(where))
        for (path, name), where in sorted(found.items())
    ]


class DiffRow(BaseModel):
    path: str
    name: str
    # here - есть только здесь, there - только там, differs - значения разные,
    # same - совпадают, unknown - сравнить нечем (запертая панель, нет права
    # читать, шифрование в браузере).
    state: str


class DiffOut(BaseModel):
    other: str
    rows: list[DiffRow]
    # Сколько ключей совпало: их не перечисляем, но знать их число полезно -
    # "отличаются два из сорока" и "два из двух" это разные новости.
    same: int


@router.get("/diff", response_model=DiffOut)
async def diff_environments(
    env_id: int,
    other: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: BoxDep,
) -> DiffOut:
    """Чем это окружение отличается от соседнего.

    Значения наружу не отдаются: панель сравнивает их у себя и сообщает только
    "совпадает" или "отличается". Поэтому и права нужны обычные - видеть ключи
    здесь и там; чтобы сравнивать сами значения, нужно право читать их в обоих
    окружениях, иначе состояние остается неизвестным.

    Проект с шифрованием в браузере сравнить нельзя: сервер видит шифротекст, и
    "отличается" означало бы разницу случайных байтов, а не значений.
    """
    environment = await _guard_any(session, user, env_id, access.LIST)
    neighbour = await _env(session, other)
    if neighbour.project_id != environment.project_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Сравнивать можно окружения одного проекта"
        )
    await _guard_any(session, user, other, access.LIST)

    project = await session.get(Project, environment.project_id)
    unsealed = box.unsealed and not (project and project.e2e)
    # Каждая папка решается сама: запрет на /private не дает ни имен оттуда, ни
    # "совпадает" про значения, которых человек прочитать не может. Раньше
    # сравнение было оракулом: положил догадку у себя - узнал, угадал ли.
    list_here = await _checker(session, user, environment, access.LIST)
    list_there = await _checker(session, user, neighbour, access.LIST)
    read_here = await _checker(session, user, environment, access.READ)
    read_there = await _checker(session, user, neighbour, access.READ)

    # Состав берем по списку ключей, значения - пачкой и только если их вообще
    # разрешено читать: сравнение состава работает и у запертой панели.
    here_keys = {
        (secret.path, secret.name)
        for secret, _level in await secrets_store.effective_list(session, env_id)
        if list_here(secret.path)
    }
    there_keys = {
        (secret.path, secret.name)
        for secret, _level in await secrets_store.effective_list(session, other)
        if list_there(secret.path)
    }
    here_values = await secrets_store.values_of(session, box, env_id) if unsealed else {}
    there_values = await secrets_store.values_of(session, box, other) if unsealed else {}

    rows: list[DiffRow] = []
    same = 0
    for place in sorted(here_keys | there_keys):
        if place not in here_keys:
            rows.append(DiffRow(path=place[0], name=place[1], state="there"))
            continue
        if place not in there_keys:
            rows.append(DiffRow(path=place[0], name=place[1], state="here"))
            continue
        if not (unsealed and read_here(place[0]) and read_there(place[0])):
            rows.append(DiffRow(path=place[0], name=place[1], state="unknown"))
            continue
        if here_values.get(place) == there_values.get(place):
            same += 1
        else:
            rows.append(DiffRow(path=place[0], name=place[1], state="differs"))

    # Значения панель прочитала - это стоит записи, хотя человек их не увидел.
    # Ключи не перечисляем: в журнале и так есть, кто с чем сравнивал.
    await audit.record(
        session,
        actor=user.username,
        action="env_compared",
        target=f"{env_id}:{other}",
        detail=f"различий {len(rows)}, совпало {same}",
        ip=peer_ip(request),
    )
    await session.commit()

    return DiffOut(other=neighbour.name, rows=rows, same=same)


class MutedOut(BaseModel):
    path: str
    name: str
    code: str
    text: str
    muted_by: str


@router.get("/lint/mutes", response_model=list[MutedOut])
async def list_mutes(
    env_id: int,
    user: CurrentUser,
    session: SessionDep,
) -> list[MutedOut]:
    """Принятые замечания: что панель молчаливо пропускает в этом окружении.

    Без такого списка "так и надо" - решение в один конец: нажали по ошибке, и
    замечание исчезло навсегда. Значения не читаются, поэтому хватает права
    видеть ключи.
    """
    env = await _guard_any(session, user, env_id, access.LIST)
    can_list = await _checker(session, user, env, access.LIST)
    rows = await session.scalars(
        select(LintMute).where(LintMute.environment_id == env_id).order_by(LintMute.name)
    )
    return [
        MutedOut(
            path=row.path,
            name=row.name,
            code=row.code,
            text=lint.TITLES.get(row.code, row.code),
            muted_by=row.muted_by,
        )
        for row in rows
        if can_list(row.path)
    ]


class CopyIn(BaseModel):
    """Откуда берем: имя соседнего окружения того же проекта."""

    source: str
    path: str = "/"
    name: str


@router.post("/copy-from", response_model=SecretOut)
async def copy_from_neighbour(
    env_id: int,
    body: CopyIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> SecretOut:
    """Взять ключ из соседнего окружения: значение копируется сюда новой версией.

    Права спрашиваются с обеих сторон: писать здесь и читать там. Иначе перенос
    стал бы способом заглянуть в окружение, которое человеку не показывают.

    В соседнем окружении ничего не меняется, а здесь правка проходит обычным
    путем - вместе с подтверждением, если проект его требует.
    """
    env = await _guard(session, user, env_id, access.WRITE, body.path)

    source = await session.scalar(
        select(Environment).where(
            Environment.project_id == env.project_id,
            Environment.name == body.source,
        )
    )
    if source is None or source.id == env_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Такого окружения в проекте нет")

    # В проекте с шифрованием в браузере значение переезжает запечатанным, как
    # есть: ключ проекта у всех его окружений один, и копия раскроется там же,
    # где оригинал. Свой слой сервер снимает и накладывает заново ключом этого
    # окружения, а открытого текста не видит ни на каком шаге.
    await access.require(
        session,
        user,
        access.READ,
        access.Scope(project_id=env.project_id, environment_id=source.id, path=body.path),
    )

    # Значение берется таким, каким его отдает источник, в том числе
    # унаследованным: ровно так его и предлагает список недостающих ключей.
    found = await secrets_store.resolve(session, source.id, body.path, body.name)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Такого ключа здесь нет")
    value = await secrets_store.read_value(session, box, found[0])

    pending = await _needs_approval(session, user, env)
    version = await secrets_store.set_value(
        session,
        box,
        env_id=env_id,
        path=body.path,
        name=body.name,
        value=value,
        author=user.username,
        comment=f"взято из {source.name}",
        pending=pending,
        legacy_name=True,
    )
    await audit.record(
        session,
        actor=user.username,
        action="secret_pending" if pending else "secret_written",
        target=f"{env_id}:{version.path_at}:{version.name_at}",
        detail=f"версия {version.version} · взято из {source.name}",
        ip=peer_ip(request),
    )
    await _tell_about_prod(
        session, env, user, [version.name_at], f"взял значение из {source.name}"
    )
    await session.commit()
    return SecretOut(
        name=version.name_at,
        path=version.path_at,
        version=version.version,
        updated_by=user.username,
        pending=pending,
    )


class IdleRow(BaseModel):
    path: str
    name: str
    # Когда значение правили в последний раз. Читать его могли и не разу - тогда
    # это единственная дата, которая про ключ вообще известна.
    updated_at: str = ""


class IdleOut(BaseModel):
    rows: list[IdleRow]
    # С какой даты в журнале есть записи. Если журнал начали вести позже, чем
    # смотрит вопрос, "никто не читал" означает лишь "в журнале этого нет".
    log_since: str = ""
    days: int


@router.get("/idle", response_model=IdleOut)
async def idle_secrets(
    env_id: int,
    user: CurrentUser,
    session: SessionDep,
    days: int = 365,
) -> IdleOut:
    """Ключи этого окружения, которых за столько-то дней никто не открывал.

    Считаются обращения людей: в журнале они записаны поименно. Агент забирает
    окружение целиком и отдельные ключи не называет, поэтому список говорит про
    людей, а не про то, что значение никому не нужно. Решение об удалении все
    равно принимает человек - панель только показывает, с чего начать.

    Унаследованные ключи не считаются: они живут в родителе, там их и смотрят.
    """
    env = await _guard_any(session, user, env_id, access.LIST)
    can_list = await _checker(session, user, env, access.LIST)
    days = max(1, min(days, 3650))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Чтение через дочернее окружение - тоже чтение этого ключа: stage,
    # наследующий от base, читает значение base, и такой ключ не кандидат на
    # удаление. Журнал пишет чтение на то окружение, через которое читали.
    envs = await _descendants(session, env_id)
    seen: set[str] = set()
    for env in envs:
        rows = await session.scalars(
            select(AuditLog.target).where(
                AuditLog.action == "secret_read",
                AuditLog.ts >= since,
                AuditLog.target.like(f"{env}:%"),
            )
        )
        seen.update(target for target in rows if target)

    first = await session.scalar(select(func.min(AuditLog.ts)))

    out: list[IdleRow] = []
    for secret, level in await secrets_store.effective_list(session, env_id):
        if secret.environment_id != env_id or not can_list(secret.path):
            continue
        # Строка журнала сверяется целиком, а не разбирается по двоеточию: в
        # папке и в имени двоеточие бывает, и ключ из /x:y, который только что
        # прочитали, числился непрочитанным.
        # Строка журнала обрезана до TARGET_MAX - сверяем так же обрезанную.
        # Чтение через наследника засчитывается, только если там ключ берется
        # отсюда: свое переопределение в дочернем окружении - другой ключ.
        read = f"{env_id}:{secret.path}:{secret.name}"[: audit.TARGET_MAX] in seen
        for child in envs[1:]:
            if read:
                break
            if f"{child}:{secret.path}:{secret.name}"[: audit.TARGET_MAX] not in seen:
                continue
            found = await secrets_store.resolve(session, child, secret.path, secret.name)
            read = found is not None and found[1] == env_id
        if read:
            continue
        version = await secrets_store.current_version(session, secret)
        out.append(
            IdleRow(
                path=secret.path,
                name=secret.name,
                updated_at=_iso(version.created_at) if version else "",
            )
        )
    return IdleOut(rows=out, log_since=_iso(first), days=days)


async def _descendants(session: AsyncSession, env_id: int) -> list[int]:
    """Окружение и все, что наследует от него, на любую глубину."""
    out, frontier = [env_id], [env_id]
    while frontier:
        children = list(
            await session.scalars(select(Environment.id).where(Environment.parent_id.in_(frontier)))
        )
        frontier = [child for child in children if child not in out]
        out.extend(frontier)
    return out


class SameRow(BaseModel):
    project: str
    environment: str
    path: str
    name: str


@router.get("/same", response_model=list[SameRow])
async def same_value(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
    name: str = Query(min_length=1, max_length=200),
    path: str = Query(default="/", max_length=200),
) -> list[SameRow]:
    """Где еще лежит ровно это же значение.

    Вопрос задают, когда пароль засветился: искать его перебором по двум сотням
    окружений - работа на день. Панель сравнивает значения у себя и отдает
    только места; самого значения в ответе нет.

    Смотрим лишь там, где человеку и так разрешено читать: иначе ответ "такой же
    пароль есть вон в том проекте" сам по себе рассказывал бы о чужом окружении.
    """
    await _guard(session, user, env_id, access.READ, path)
    secret = await _secret_or_404(session, env_id, path, name)
    value = await secrets_store.read_value(session, box, secret)

    projects = {p.id: p for p in await session.scalars(select(Project))}
    out: list[SameRow] = []
    for environment in await session.scalars(select(Environment)):
        project = projects.get(environment.project_id)
        if project is None or project.e2e:
            # Значения шифрует браузер: сервер видит шифротекст и сравнивать его
            # с открытым значением бессмысленно.
            continue
        can_read = await _checker(session, user, environment, access.READ)
        if not any(can_read(p) for p in await secrets_store.env_paths(session, environment.id)):
            continue
        for (other_path, other_name), other_value in (
            await secrets_store.values_of(session, box, environment.id)
        ).items():
            if environment.id == env_id and other_path == path and other_name == name:
                continue
            # Место, которое человек не может прочитать, в ответ не идет:
            # иначе "совпадает с /private/SECRET" было бы оракулом угадывания.
            if not can_read(other_path):
                continue
            if other_value != value:
                continue
            out.append(
                SameRow(
                    project=project.slug,
                    environment=environment.name,
                    path=other_path,
                    name=other_name,
                )
            )

    await audit.record(
        session,
        actor=user.username,
        action="secret_matched",
        target=f"{env_id}:{path}:{name}",
        detail=f"совпадений {len(out)}",
        ip=peer_ip(request),
    )
    await session.commit()
    return out


async def _subject_name(session: SessionDep, policy: Policy) -> str:
    """Имя того, кому выдано право. Пропавший субъект показываем номером: строка
    в списке важнее, чем её красота, - по ней видно, что право осталось."""
    if policy.subject_type == "user":
        found = await session.get(User, policy.subject_id)
        return found.username if found else f"#{policy.subject_id}"
    if policy.subject_type == "machine":
        machine = await session.get(MachineIdentity, policy.subject_id)
        return machine.name if machine else f"#{policy.subject_id}"
    group = await session.get(Group, policy.subject_id)
    return group.name if group else f"#{policy.subject_id}"


class WhoRow(BaseModel):
    subject: str
    kind: str
    actions: list[str]
    effect: str
    until: str = ""
    # Право выдано на весь проект, а не на это окружение: снимать его здесь
    # некому, и знать об этом полезно.
    whole_project: bool = False


@router.get("/who", response_model=list[WhoRow])
async def who_sees(
    env_id: int,
    user: MaintainerUser,
    session: SessionDep,
) -> list[WhoRow]:
    """Кому видно это окружение: люди, группы и машины.

    То же, что в разделе "Доступ", но про одно место. Там права лежат плоским
    списком по всей панели, и "кто видит прод" собирают глазами.

    Список прав - чувствительная вещь сама по себе, поэтому он открыт тем, кто
    и так распоряжается доступом и кому видно само окружение.
    """
    env = await _guard(session, user, env_id, access.LIST)
    rows = await session.scalars(
        select(Policy).where(
            (Policy.environment_id == env_id)
            | ((Policy.environment_id.is_(None)) & (Policy.project_id == env.project_id))
            | ((Policy.environment_id.is_(None)) & (Policy.project_id.is_(None)))
        )
    )
    now = datetime.now(timezone.utc)
    out: list[WhoRow] = []
    for policy in rows:
        if policy.expires_at is not None and to_utc(policy.expires_at) < now:
            continue
        out.append(
            WhoRow(
                subject=await _subject_name(session, policy),
                kind=policy.subject_type,
                actions=sorted(access.policy_actions(policy)),
                effect=policy.effect,
                until=_iso(policy.expires_at),
                whole_project=policy.environment_id is None,
            )
        )
    out.sort(key=lambda row: (row.kind, row.subject))
    return out


class EventRow(BaseModel):
    at: str
    actor: str
    action: str
    # Имя ключа, если событие про конкретный ключ. Пусто - событие про
    # окружение целиком (импорт, смена ключа шифрования).
    key: str = ""
    detail: str = ""


@router.get("/events", response_model=list[EventRow])
async def env_events(
    env_id: int,
    user: CurrentUser,
    session: SessionDep,
    limit: int = 20,
) -> list[EventRow]:
    """Что происходило в этом окружении в последнее время.

    То же, что видно в журнале с фильтром, но на месте: вопрос "кто это менял"
    возникает ровно тогда, когда смотришь на ключи, и уходить за ответом в
    другой раздел - лишний шаг.

    Значений здесь нет и быть не может: журнал их не хранит вовсе.
    """
    env = await _guard_any(session, user, env_id, access.LIST)
    can_list = await _checker(session, user, env, access.LIST)
    limit = max(1, min(limit, 100))
    rows = await session.scalars(
        select(AuditLog)
        .where(AuditLog.target.like(f"{env_id}:%") | (AuditLog.target == str(env_id)))
        .order_by(AuditLog.id.desc())
        .limit(limit)
    )
    # Подпись ключа берется по точному совпадению строки журнала с ключами
    # окружения: разбор по двоеточию путал папку /x:y с ключом y в папке /x.
    # Ключа, которого уже нет, в окружении не найти - тогда разбор, как раньше.
    known: dict[str, tuple[str, str]] = {}
    for secret, _level in await secrets_store.effective_list(session, env_id):
        known[f"{env_id}:{secret.path}:{secret.name}"[: audit.TARGET_MAX]] = (
            secret.path,
            secret.name if secret.path == "/" else f"{secret.path}/{secret.name}",
        )
    out: list[EventRow] = []
    for row in rows:
        place, key = known.get(row.target or "", ("", ""))
        parts = (row.target or "").split(":", 2)
        if not key and len(parts) == 3:
            place = parts[1]
            key = parts[2] if parts[1] == "/" else f"{parts[1]}/{parts[2]}"
        # Событие про ключ из папки, которую человек не видит, в ленту не идет:
        # имя ключа - тоже сведения.
        if key and not can_list(place or "/"):
            continue
        out.append(
            EventRow(
                at=_iso(row.ts),
                actor=row.actor,
                action=row.action,
                key=key,
                detail=_hide_closed_place(row.detail or "", can_list),
            )
        )
    return out


def _hide_closed_place(text: str, can_list: access.PlaceCheck) -> str:
    """Прежнее место ключа в подробности переименования ("было /private:KEY",
    "переименован из /private:KEY") - не для того, кто эту папку не видит.

    В пути и в имени бывает двоеточие, поэтому разрез неоднозначен: прячем,
    если закрыта папка при любом из разрезов.
    """
    for prefix, closed in (("было ", "было в закрытой папке"), ("переименован из ", "переименован из закрытой папки")):
        if not text.startswith(prefix):
            continue
        rest = text[len(prefix):]
        place, _sep, tail = rest.partition(" · ")
        cuts = [i for i, ch in enumerate(place) if ch == ":"]
        # Путь нормализуем: версии до 1.0.0 писали его как пришел в запросе
        # ("private" без слеша), и такая запись закрытую папку не прятала.
        if any(not can_list(secrets_store.normalize_path(place[:i])) for i in cuts):
            return closed + (f" · {tail}" if tail else "")
    return text


class SpreadIn(BaseModel):
    """Что раскладываем и куда: ключ отсюда и номера соседних окружений."""

    path: str = "/"
    name: str
    targets: list[int] = Field(default_factory=list, max_length=64)


class SpreadResult(BaseModel):
    environment: str
    # written - записано, pending - ждет подтверждения, denied - нет права,
    # same - там уже ровно такое значение.
    state: str


class SpreadOut(BaseModel):
    rows: list[SpreadResult]


@router.post("/spread", response_model=SpreadOut)
async def spread_secret(
    env_id: int,
    body: SpreadIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> SpreadOut:
    """Записать значение этого ключа в другие окружения проекта.

    Права спрашиваются на каждое место отдельно: читать здесь и писать там.
    Окружение, где права нет, пропускается со своей строкой в ответе - отказ
    целиком означал бы "или все, или ничего" там, где человек ждет "сделай что
    можешь и скажи, что не вышло".

    Где значение уже такое же, новая версия не заводится: история - это про
    изменения, а не про то, сколько раз нажали кнопку.
    """
    env = await _guard(session, user, env_id, access.READ, body.path)
    project = await session.get(Project, env.project_id)
    if project is not None and project.e2e:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "В проекте с шифрованием в браузере раскладывать значения нужно из браузера",
        )

    secret = await _secret_or_404(session, env_id, body.path, body.name)
    value = await secrets_store.read_value(session, box, secret)

    rows: list[SpreadResult] = []
    # Все окружения проекта из списка блокируются заранее и по возрастанию
    # номера, до первой записи в журнал. Иначе раскладка держала блокировку
    # журнала и ждала окружение, а обычная запись в то же окружение держала его
    # и ждала журнал, и Postgres отменял одну из них.
    for target_id in sorted(set(body.targets)):
        target = await session.get(Environment, target_id)
        if target is not None and target.project_id == env.project_id and target_id != env_id:
            await secrets_store.lock_env(session, target_id)
    for target_id in sorted(set(body.targets)):
        if target_id == env_id:
            continue
        target = await session.get(Environment, target_id)
        if target is None or target.project_id != env.project_id:
            continue
        scope = access.Scope(
            project_id=target.project_id, environment_id=target.id, path=body.path
        )
        if not await access.allowed(session, user, access.WRITE, scope):
            rows.append(SpreadResult(environment=target.name, state="denied"))
            continue

        # Сравниваем с тем, что окружение отдает, с учетом наследования: если
        # там ключ и так берется у родителя с тем же значением, своя копия
        # молча рвала бы наследование.
        found = await secrets_store.resolve(session, target.id, body.path, body.name)
        # "Уже такое же" сообщаем только тому, кто может прочитать это место:
        # иначе раскладка отвечала бы на вопрос "совпадает ли чужое значение с
        # моим" человеку с одним правом записи.
        if found is not None and await access.allowed(session, user, access.READ, scope):
            try:
                current = await secrets_store.read_value(session, box, found[0])
            except secrets_store.SecretNotFound:
                # Своего значения там нет (ждет подтверждения): раскладка его
                # заводит.
                current = None
            if current == value:
                rows.append(SpreadResult(environment=target.name, state="same"))
                continue

        pending = await _needs_approval(session, user, target)
        version = await secrets_store.set_value(
            session,
            box,
            env_id=target.id,
            path=body.path,
            name=body.name,
            value=value,
            author=user.username,
            comment=f"как в {env.name}",
            legacy_name=True,
            pending=pending,
        )
        await audit.record(
            session,
            actor=user.username,
            action="secret_pending" if pending else "secret_written",
            target=f"{target.id}:{version.path_at}:{version.name_at}",
            detail=f"версия {version.version} · как в {env.name}",
            ip=peer_ip(request),
        )
        rows.append(SpreadResult(environment=target.name, state="pending" if pending else "written"))
        await _tell_about_prod(
            session, target, user, [body.name], "разложил значение"
        )

    await session.commit()
    return SpreadOut(rows=rows)


@router.post("/lint/mute", status_code=status.HTTP_204_NO_CONTENT)
async def mute_note(
    env_id: int,
    body: MuteIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> None:
    """"Здесь так и надо": панель перестает показывать это замечание.

    Право спрашивается на запись: это решение о том, как выглядит окружение для
    всех, кто его откроет, а не личная настройка отображения.
    """
    await _guard(session, user, env_id, access.WRITE, body.path)
    exists = await session.scalar(
        select(LintMute).where(
            LintMute.environment_id == env_id,
            LintMute.path == body.path,
            LintMute.name == body.name,
            LintMute.code == body.code,
        )
    )
    if exists is None:
        session.add(
            LintMute(
                environment_id=env_id,
                path=body.path,
                name=body.name,
                code=body.code,
                muted_by=user.username,
            )
        )
        await audit.record(
            session,
            actor=user.username,
            action="lint_muted",
            target=f"{env_id}:{body.path}:{body.name}",
            detail=body.code,
            ip=peer_ip(request),
        )
    await session.commit()


@router.delete("/lint/mute", status_code=status.HTTP_204_NO_CONTENT)
async def unmute_note(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    name: str,
    code: str,
    path: str = "/",
) -> None:
    """Вернуть замечание: решение "так и надо" пересматривают, как любое другое."""
    await _guard(session, user, env_id, access.WRITE, path)
    row = await session.scalar(
        select(LintMute).where(
            LintMute.environment_id == env_id,
            LintMute.path == path,
            LintMute.name == name,
            LintMute.code == code,
        )
    )
    if row is not None:
        await session.delete(row)
        await audit.record(
            session,
            actor=user.username,
            action="lint_unmuted",
            target=f"{env_id}:{path}:{name}",
            detail=code,
            ip=peer_ip(request),
        )
    await session.commit()


@router.get("/values", response_model=list[ValueRow])
async def read_all_values(
    env_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> list[ValueRow]:
    """Все значения окружения разом - для окна, где их правят списком.

    Право нужно на каждую папку окружения, как у выгрузки: операция выносит
    наружу сразу все, и в журнале она стоит отдельной строкой. Отдаем структурой,
    а не текстом .env: значение в несколько строк в тексте приходится экранировать,
    и разбирать его обратно в интерфейсе - лишний способ испортить конфиг.
    """
    await _guard_whole(session, user, env_id, access.READ)
    names: dict[int, str] = {}
    out: list[ValueRow] = []
    plain = await secrets_store.values_of(session, box, env_id)
    for secret, level in await secrets_store.effective_list(session, env_id):
        if level != env_id and level not in names:
            parent = await session.get(Environment, level)
            names[level] = parent.name if parent else str(level)
        value = plain.get((secret.path, secret.name))
        if value is None:
            continue
        out.append(
            ValueRow(
                name=secret.name,
                path=secret.path,
                version=secret.current_version,
                value=value,
                inherited_from="" if level == env_id else names[level],
            )
        )
    await audit.record(
        session,
        actor=user.username,
        action="env_values_read",
        target=str(env_id),
        detail=f"ключей: {len(out)}",
        ip=peer_ip(request),
    )
    await session.commit()
    return out


@router.post("/import", response_model=ImportOut)
async def import_env(
    env_id: int,
    body: ImportIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> ImportOut:
    env = await _guard(session, user, env_id, access.WRITE, body.path)
    await refuse_below_threshold(session, user, env)
    if await secrets_store.is_e2e(session, env_id):
        # Отказ до разбора: ответ про шифрование понятнее ответа про имя в
        # пятой строке, а открытому файлу в таком проекте все равно не место.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "у проекта шифрование в браузере: файл с открытыми значениями сюда не "
            "заливается, ключи заводятся по одному, и значения запечатывает браузер",
        )
    try:
        parsed = secrets_store.parse_env(body.text, body.path)
        # Предел как у переноса: мегабайт текста - это до ста с лишним тысяч
        # ключей в одной транзакции, минута работы и все окружение под
        # блокировкой.
        if len(parsed) > MAX_IMPORT_KEYS:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"в файле {len(parsed)} ключей - больше предела {MAX_IMPORT_KEYS}: разбейте его на части",
            )
        # Файл раскладывает ключи по папкам сам - значит и право нужно на
        # каждую из них, а не только на выбранную в окне.
        for folder in sorted({row[0] for row in parsed}):
            await _guard(session, user, env_id, access.WRITE, folder)
        created, updated, skipped = await secrets_store.import_env(
            session,
            box,
            env_id=env_id,
            text=body.text,
            path=body.path,
            author=user.username,
            overwrite=body.overwrite,
        )
    except secrets_store.SealedValueRequired as exc:
        # Проект с шифрованием в браузере: файл надо запечатать до отправки,
        # и делает это сам браузер.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ValueError as exc:
        # Разбор не удался - не пишем ничего. Половина импортированного файла
        # хуже, чем ни одной строки: понять, что именно доехало, потом нельзя.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Файл не разобрался: {exc}") from exc
    await audit.record(
        session,
        actor=user.username,
        action="env_imported",
        target=str(env_id),
        detail=f"создано {created}, обновлено {updated}, пропущено {len(skipped)}",
        ip=peer_ip(request),
    )
    if created or updated:
        await _tell_about_prod(
            session,
            await _env(session, env_id),
            user,
            [f"из файла: создано {created}, обновлено {updated}"],
            "залил значения",
        )
    await session.commit()
    return ImportOut(created=created, updated=updated, skipped=skipped)


# --- снимки ----------------------------------------------------------------


async def _snapshot_or_404(session, env_id: int, snapshot_id: int) -> EnvSnapshot:
    snapshot = await session.get(EnvSnapshot, snapshot_id)
    if snapshot is None or snapshot.environment_id != env_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Снимок не найден")
    return snapshot


@router.get("/snapshots", response_model=list[SnapshotOut])
async def list_snapshots(
    env_id: int, user: CurrentUser, session: SessionDep
) -> list[SnapshotOut]:
    await _guard(session, user, env_id, access.LIST)
    rows = await session.scalars(
        select(EnvSnapshot)
        .where(EnvSnapshot.environment_id == env_id)
        .order_by(EnvSnapshot.id.desc())
    )
    out: list[SnapshotOut] = []
    for snapshot in rows:
        plan_items = await secrets_store.snapshot_items_count(session, snapshot)
        out.append(
            SnapshotOut(
                id=snapshot.id,
                name=snapshot.name,
                author=snapshot.author,
                created_at=to_utc(snapshot.created_at).isoformat() if snapshot.created_at else "",
                keys=plan_items,
            )
        )
    return out


@router.post("/snapshots", response_model=SnapshotOut, status_code=status.HTTP_201_CREATED)
async def create_snapshot(
    env_id: int,
    body: SnapshotIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> SnapshotOut:
    await _guard(session, user, env_id, access.WRITE)
    try:
        snapshot = await secrets_store.snapshot_create(
            session, env_id=env_id, name=body.name, author=user.username
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await audit.record(
        session,
        actor=user.username,
        action="snapshot_created",
        target=f"{env_id}:{body.name}",
        ip=peer_ip(request),
    )
    await session.commit()
    count = await secrets_store.snapshot_items_count(session, snapshot)
    return SnapshotOut(
        id=snapshot.id,
        name=snapshot.name,
        author=snapshot.author,
        created_at=to_utc(snapshot.created_at).isoformat() if snapshot.created_at else "",
        keys=count,
    )


@router.get("/snapshots/{snapshot_id}/plan", response_model=list[PlanRow])
async def snapshot_plan(
    env_id: int, snapshot_id: int, user: CurrentUser, session: SessionDep
) -> list[PlanRow]:
    """Что изменится при восстановлении. Значений здесь нет - только имена и
    действия, поэтому предпросмотр доступен и тому, кто не читает значения."""
    env = await _guard_any(session, user, env_id, access.LIST)
    can_list = await _checker(session, user, env, access.LIST)
    snapshot = await _snapshot_or_404(session, env_id, snapshot_id)
    plan = await secrets_store.snapshot_plan(session, snapshot)
    return [PlanRow(path=p, name=n, action=a) for p, n, a in plan if can_list(p)]


SNAPSHOT_GONE = "Снимок удалили, пока шло восстановление: окружение не тронуто"


@router.post("/snapshots/{snapshot_id}/restore", response_model=RestoreOut)
async def restore_snapshot(
    env_id: int,
    snapshot_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> RestoreOut:
    # Восстановление меняет ключи во всех папках: право на корень пускало
    # вернуть старое значение в закрытую папку и удалить там новое.
    env = await _guard_whole(session, user, env_id, access.WRITE)
    await refuse_below_threshold(session, user, env)
    snapshot = await _snapshot_or_404(session, env_id, snapshot_id)
    plan_paths = {p for p, _n, _a in await secrets_store.snapshot_plan(session, snapshot)}
    if not await access.covers_whole(session, user, access.WRITE, env.project_id, env.id, plan_paths):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f'В окружении есть папки, где у вас нет права "{access.TITLES[access.WRITE]}": '
            "действие над всем окружением недоступно",
        )
    # Восстановление убирает ключи, заведенные после снимка: без права удалять
    # это было бы удаление в обход запрета на удаление. Проверка - под
    # блокировкой окружения: ключ, заведенный между проверкой и
    # восстановлением, иначе удалялся бы без нее.
    await secrets_store.lock_env(session, env_id)
    if not await secrets_store.snapshot_exists(session, snapshot.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, SNAPSHOT_GONE)
    can_read = await _checker(session, user, env, access.READ)
    can_delete = await _checker(session, user, env, access.DELETE)
    if not all(can_delete(path) for path in await secrets_store.snapshot_removals(session, snapshot)):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Восстановление уберет ключи, заведенные после снимка, а права удалять их у вас нет",
        )
    try:
        restored, removed = await secrets_store.snapshot_restore(
            session, box, snapshot, author=user.username, can_read=can_read
        )
    except secrets_store.SnapshotGone as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_404_NOT_FOUND, SNAPSHOT_GONE) from exc
    except secrets_store.RestoreCrossesFolder as exc:
        # Ничего не записано: изменения этого запроса откатываются вместе с
        # сессией.
        await session.rollback()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Восстановление перенесет старое значение из папки, где у вас нет права читать значения",
        ) from exc
    await audit.record(
        session,
        actor=user.username,
        action="snapshot_restored",
        target=f"{env_id}:{snapshot.name}",
        detail=f"возвращено {restored}, удалено {removed}",
        ip=peer_ip(request),
    )
    await session.commit()
    return RestoreOut(restored=restored, removed=removed)


@router.delete("/snapshots/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_snapshot(
    env_id: int,
    snapshot_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> None:
    """Удаление снимка не трогает ни одного значения: снимок - это только набор
    номеров версий, а сами версии живут в истории."""
    await _guard(session, user, env_id, access.WRITE)
    # Под блокировкой окружения: восстановление этого же снимка, которое уже
    # идет, дорабатывает до конца, а не видит пустой снимок.
    await secrets_store.lock_env(session, env_id)
    snapshot = await _snapshot_or_404(session, env_id, snapshot_id)
    name = snapshot.name
    await session.delete(snapshot)
    await audit.record(
        session,
        actor=user.username,
        action="snapshot_deleted",
        target=f"{env_id}:{name}",
        ip=peer_ip(request),
    )
    await session.commit()


# --- подтверждение изменений ----------------------------------------------


class PendingOut(BaseModel):
    name: str
    path: str
    version: int
    author: str
    comment: str
    created_at: str
    deleted: bool


class ReviewIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(default="/", max_length=200)
    version: int = Field(ge=1)
    note: str = Field(default="", max_length=500)


async def _pending_or_404(session: SessionDep, secret, version_no: int):
    version = await secrets_store.get_version(session, secret, version_no)
    if version is None or version.status != secrets_store.STATUS_PENDING:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Такой правки, ожидающей подтверждения, нет"
        )
    return version


def _can_review(reviewer, author_name: str, author_role_level: int) -> None:
    """Подтверждает тот, кто выше автора, и не сам автор.

    Оба правила нужны. Без первого подтверждение становится формальностью между
    равными, без второго - человек подтверждает себя сам, и вся церемония
    оказывается кнопкой "применить в два клика".
    """
    if reviewer.username == author_name:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Свою правку подтверждает кто-то другой"
        )
    if roles.level(reviewer.role) <= author_role_level:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Подтвердить может только роль выше той, что предложила правку",
        )


async def _author_level(session: SessionDep, username: str) -> int:
    from app.models import User

    author = await session.scalar(select(User).where(User.username == username))
    return roles.level(author.role) if author else 0


@router.get("/pending", response_model=list[PendingOut])
async def list_pending(
    env_id: int, user: CurrentUser, session: SessionDep
) -> list[PendingOut]:
    env = await _guard_any(session, user, env_id, access.LIST)
    can_list = await _checker(session, user, env, access.LIST)
    rows = [
        (secret, version)
        for secret, version in await secrets_store.pending_versions(session, env_id)
        if can_list(version.path_at)
    ]
    return [
        PendingOut(
            name=version.name_at,
            path=version.path_at,
            version=version.version,
            author=version.author,
            comment=version.comment,
            created_at=to_utc(version.created_at).isoformat() if version.created_at else "",
            deleted=version.deleted,
        )
        for _secret, version in rows
    ]


@router.post("/secret/approve", response_model=SecretOut)
async def approve_secret(
    env_id: int,
    body: ReviewIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> SecretOut:
    await _guard(session, user, env_id, access.APPROVE, body.path)
    secret = await _secret_or_404(session, env_id, body.path, body.name)
    version = await _pending_or_404(session, secret, body.version)
    _can_review(user, version.author, await _author_level(session, version.author))
    try:
        await secrets_store.approve_version(
            session, secret, version, reviewer=user.username, note=body.note
        )
    except secrets_store.NotPending as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Такой правки, ожидающей подтверждения, нет"
        ) from exc
    except secrets_store.StaleProposal as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Ключ изменили после этой правки: ее нужно предложить заново",
        ) from exc
    await audit.record(
        session,
        actor=user.username,
        action="secret_approved",
        target=f"{env_id}:{version.path_at}:{version.name_at}",
        detail=f"версия {version.version}, автор {version.author}",
        ip=peer_ip(request),
    )
    await session.commit()
    return SecretOut(
        name=version.name_at,
        path=version.path_at,
        version=version.version,
        updated_by=version.author,
    )


@router.post("/secret/reject", status_code=status.HTTP_204_NO_CONTENT)
async def reject_secret(
    env_id: int,
    body: ReviewIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> None:
    await _guard(session, user, env_id, access.APPROVE, body.path)
    secret = await _secret_or_404(session, env_id, body.path, body.name)
    version = await _pending_or_404(session, secret, body.version)
    _can_review(user, version.author, await _author_level(session, version.author))
    await secrets_store.lock_env(session, env_id)
    try:
        await secrets_store.reject_version(
            session, version, reviewer=user.username, note=body.note
        )
    except secrets_store.NotPending as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Такой правки, ожидающей подтверждения, нет"
        ) from exc
    await audit.record(
        session,
        actor=user.username,
        action="secret_rejected",
        target=f"{env_id}:{version.path_at}:{version.name_at}",
        detail=f"версия {version.version}, автор {version.author}: {body.note}",
        ip=peer_ip(request),
    )
    await session.commit()


# --- наследование ----------------------------------------------------------


class InheritIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    path: str = Field(default="/", max_length=200)


@router.post("/secret/inherit", response_model=SecretOut)
async def stop_override(
    env_id: int,
    body: InheritIn,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    box: UnsealedBox,
) -> SecretOut:
    """Убрать свое значение и вернуться к родительскому.

    Это версия, а не удаление строки: история переопределения остается, и видно,
    когда его завели и когда от него отказались.
    """
    env = await _guard(session, user, env_id, access.WRITE, body.path)
    await refuse_below_threshold(session, user, env)
    if env.parent_id is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "У окружения нет родителя — наследовать не от кого"
        )
    secret = await secrets_store.get_secret(session, env_id, body.path, body.name)
    if secret is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Здесь нет своего значения")
    version = await secrets_store.stop_override(session, box, secret, author=user.username)
    await audit.record(
        session,
        actor=user.username,
        action="secret_inherited",
        target=f"{env_id}:{body.path}:{body.name}",
        detail="снято переопределение",
        ip=peer_ip(request),
    )
    await session.commit()
    return SecretOut(
        name=version.name_at,
        path=version.path_at,
        version=version.version,
        updated_by=user.username,
    )
