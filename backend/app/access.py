"""Кто и что может делать с секретами.

Модель простая и намеренно скучная:

  * **владелец панели может все.** Иначе первым же делом можно запереть самого
    себя, а восстанавливаться из этого пришлось бы правкой базы;
  * **всем остальным доступ дается только политиками.** Нет политики - нет
    доступа: по умолчанию закрыто, а не "роль что-нибудь да разрешит";
  * **запрет сильнее разрешения.** Отобрать доступ должно быть одним действием,
    а не поиском всех мест, где он был выдан;
  * **истекшая политика не действует**, и это проверяется здесь, а не
    напоминанием в календаре;
  * **наблюдатель только смотрит**: ему действуют "видеть ключи" и "читать
    значения", что бы ни было выдано. Иначе роль ничем не отличалась от
    разработчика, а галочка "менять" в общей группе молча давала запись.

Действия разделены мельче, чем "чтение и запись", ровно ради одного случая:
`list` показывает, какие ключи есть, `read` показывает их значения. Разработчику
нужно первое и не нужно второе.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import GroupMember, Policy, Project, User
from app.roles import OWNER, VIEWER

LIST = "list"
READ = "read"
WRITE = "write"
DELETE = "delete"
ROTATE = "rotate"
APPROVE = "approve"

ACTIONS = (LIST, READ, WRITE, DELETE, ROTATE, APPROVE)

# Что действует наблюдателю.
VIEWER_ACTIONS = frozenset({LIST, READ})

TITLES = {
    LIST: "видеть ключи",
    READ: "читать значения",
    WRITE: "менять значения",
    DELETE: "удалять ключи",
    ROTATE: "менять ключ окружения",
    APPROVE: "подтверждать изменения",
}


@dataclass(frozen=True)
class Scope:
    """Место, к которому просят доступ."""

    project_id: int | None = None
    environment_id: int | None = None
    path: str = "/"


def normalize_prefix(prefix: str) -> str:
    cleaned = "/" + "/".join(part for part in prefix.split("/") if part)
    return cleaned


def path_covered(prefix: str, path: str) -> bool:
    """Путь входит в область политики.

    Префиксом, а не шаблоном: `/db` покрывает `/db` и `/db/replica`, но не
    `/dbx`. Шаблоны выглядят гибче, но читать их глазами в момент разбора
    "почему у человека нет доступа" заметно тяжелее.
    """
    prefix = normalize_prefix(prefix)
    path = normalize_prefix(path)
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def policy_actions(policy: Policy) -> set[str]:
    return {a.strip() for a in policy.actions.split(",") if a.strip()}


def alive(policy: Policy, now: datetime) -> bool:
    if policy.expires_at is None:
        return True
    expires = policy.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > now


def matches(policy: Policy, action: str, scope: Scope) -> bool:
    if action not in policy_actions(policy):
        return False
    if policy.project_id is not None and policy.project_id != scope.project_id:
        return False
    if policy.environment_id is not None and policy.environment_id != scope.environment_id:
        return False
    return path_covered(policy.path_prefix, scope.path)


async def policies_for(session: AsyncSession, user: User) -> list[Policy]:
    """Политики человека: выданные лично и через группы."""
    group_ids = list(
        await session.scalars(
            select(GroupMember.group_id).where(GroupMember.user_id == user.id)
        )
    )
    rows = await session.scalars(
        select(Policy).where(
            (
                (Policy.subject_type == "user") & (Policy.subject_id == user.id)
            )
            | (
                (Policy.subject_type == "group") & Policy.subject_id.in_(group_ids or [-1])
            )
        )
    )
    return list(rows)


def decide(
    policies: list[Policy], user: User, action: str, scope: Scope, now: datetime
) -> bool:
    """Решение по уже загруженным политикам.

    Отдельно от `allowed`, потому что есть места, где решение принимается
    подряд для сотни строк - поиск по ключам во всех проектах. Ходить в базу за
    политиками на каждую строку там нельзя.
    """
    if user.role == VIEWER and action not in VIEWER_ACTIONS:
        return False
    matched = [p for p in policies if alive(p, now) and matches(p, action, scope)]
    if any(p.effect == "deny" for p in matched):
        return False
    for policy in matched:
        if policy.effect != "allow":
            continue
        # Политика с требованием второго фактора не действует, пока фактор не
        # включен. Это не напоминание, а условие: "включите 2FA, тогда и будет
        # доступ", а не "доступ есть, но вы все-таки включите".
        if policy.require_2fa and not user.totp_enabled:
            continue
        return True
    return False


async def allowed(
    session: AsyncSession, user: User, action: str, scope: Scope
) -> bool:
    if user.role == OWNER:
        return True
    return decide(
        await policies_for(session, user), user, action, scope, datetime.now(timezone.utc)
    )


async def require(
    session: AsyncSession, user: User, action: str, scope: Scope
) -> None:
    """Бросает 403, если действие не разрешено."""
    if await allowed(session, user, action, scope):
        return
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        f"Нет права «{TITLES.get(action, action)}» в этом месте",
    )


async def visible_in(
    session: AsyncSession, user: User, action: str, project_id: int, env_ids: list[int]
) -> set[int]:
    """Окружения из env_ids, где у человека есть право action хоть в какой-то папке.

    Проверка по корню здесь не годится: право на `/db` корень не покрывает, и
    человек с правом на папку не видел бы окружения, в котором она лежит.
    Поэтому решение принимается в том месте, куда смотрит каждое разрешение, и
    запреты действуют как везде.
    """
    if user.role == OWNER:
        return set(env_ids)
    policies = await policies_for(session, user)
    now = datetime.now(timezone.utc)
    out: set[int] = set()
    for policy in policies:
        if policy.effect != "allow" or not alive(policy, now):
            continue
        if action not in policy_actions(policy) or policy.project_id not in (None, project_id):
            continue
        for env_id in env_ids:
            if env_id in out or policy.environment_id not in (None, env_id):
                continue
            scope = Scope(project_id=project_id, environment_id=env_id, path=policy.path_prefix or "/")
            if decide(policies, user, action, scope, now):
                out.add(env_id)
    return out


# --- права на окружение целиком и по папкам -----------------------------------
#
# Политика бывает на папку, и запрет на папку сильнее разрешения на корень.
# Проверка "по корню" поэтому годится только для одного ключа в корне. Все,
# что отдает или меняет окружение целиком (выгрузка, все значения, сравнение,
# снимки, машина), и все списки имен решают по каждому пути отдельно. Раньше
# запрет на /private обходился выгрузкой, снимком, машиной и переименованием.

PlaceCheck = Callable[[str], bool]


async def place_check(
    session: AsyncSession, user: User, action: str, project_id: int, env_id: int
) -> PlaceCheck:
    """Решатель для путей одного окружения: разрешено ли действие по пути."""
    if user.role == OWNER:
        return lambda _path: True
    policies = await policies_for(session, user)
    now = datetime.now(timezone.utc)
    cache: dict[str, bool] = {}

    def check(path: str) -> bool:
        if path not in cache:
            cache[path] = decide(
                policies, user, action, Scope(project_id=project_id, environment_id=env_id, path=path), now
            )
        return cache[path]

    return check


async def place_checks(
    session: AsyncSession, user: User, action: str, envs: Iterable[tuple[int, int]]
) -> dict[int, PlaceCheck]:
    """place_check для многих окружений (пары проект, окружение) разом:
    политики загружаются один раз, а не на каждое окружение главной страницы."""
    pairs = list(envs)
    if user.role == OWNER:
        return {env_id: (lambda _path: True) for _project_id, env_id in pairs}
    policies = await policies_for(session, user)
    now = datetime.now(timezone.utc)
    out: dict[int, PlaceCheck] = {}
    for project_id, env_id in pairs:
        cache: dict[str, bool] = {}

        def check(path: str, project_id=project_id, env_id=env_id, cache=cache) -> bool:
            if path not in cache:
                cache[path] = decide(
                    policies, user, action, Scope(project_id=project_id, environment_id=env_id, path=path), now
                )
            return cache[path]

        out[env_id] = check
    return out


def interesting_paths(policies: Iterable[Policy], paths: Iterable[str]) -> set[str]:
    """Пути, по которым решение может меняться: корень, папки ключей и все
    префиксы политик. Между ними решение одинаковое, поэтому проверить их -
    значит проверить все окружение."""
    out = {"/"}
    out.update(normalize_prefix(p) for p in paths)
    out.update(normalize_prefix(p.path_prefix or "/") for p in policies)
    return out


def moments(now: datetime, policies: Iterable[Policy]) -> list[datetime]:
    """Сейчас и каждый будущий момент, когда кончается чья-то политика.

    Права меняются только в эти моменты. Сравнение "может ли один все, что
    другой" в одной точке "сейчас" пропускало временное право: ответственный с
    prod до завтра выдавал машине prod бессрочно, и его доступ переживал сам
    себя.
    """
    out = {now}
    for policy in policies:
        if policy.expires_at is None:
            continue
        expires = policy.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires > now:
            out.add(expires)
    return sorted(out)


async def whole_until(
    session: AsyncSession,
    user: User,
    action: str,
    project_id: int,
    env_id: int,
    paths: Iterable[str],
) -> tuple[bool, datetime | None]:
    """Есть ли право действия на все окружение сейчас и до какого момента оно
    держится без перерыва (None - без срока). По нему ставится срок тому, что
    человек выдает от себя: подключенной им машине."""
    if user.role == OWNER:
        return True, None
    policies = await policies_for(session, user)
    places = interesting_paths(policies, list(paths))

    def whole(at: datetime) -> bool:
        return all(
            decide(policies, user, action, Scope(project_id=project_id, environment_id=env_id, path=path), at)
            for path in places
        )

    when = moments(datetime.now(timezone.utc), policies)
    if not whole(when[0]):
        return False, None
    for at in when[1:]:
        if not whole(at):
            return True, at
    return True, None


async def covers_whole(
    session: AsyncSession,
    user: User,
    action: str,
    project_id: int,
    env_id: int,
    paths: Iterable[str],
) -> bool:
    """Есть ли право действия на каждую папку окружения (paths - папки его
    ключей, свои и унаследованные)."""
    if user.role == OWNER:
        return True
    policies = await policies_for(session, user)
    now = datetime.now(timezone.utc)
    return all(
        decide(policies, user, action, Scope(project_id=project_id, environment_id=env_id, path=path), now)
        for path in interesting_paths(policies, paths)
    )


@dataclass(frozen=True)
class Potential:
    """Учетка в том виде, в какой ее приведет тот, кто знает ее пароль.

    Сброс пароля сравнивал права с тем, что цель может сейчас: политика с
    require_2fa не считалась, пока второй фактор выключен, а права записи у
    наблюдателя - пока он наблюдатель. Но со своим паролем от чужой учетки
    второй фактор включают за минуту, а роль ответственный повышает сам.
    """

    role: str
    totp_enabled: bool = True


def potential(user: User) -> Potential:
    """Наибольшее, что может учетка: второй фактор включен, ограничение роли
    наблюдателя снято (повысить ее может тот, кто сбросил пароль)."""
    return Potential(role="" if user.role == VIEWER else user.role)


def covers(
    actor_policies: list[Policy],
    actor: User,
    target_policies: list[Policy],
    target_decide: Callable[[str, Scope, datetime], bool],
    actions: Iterable[str],
    now: datetime,
) -> bool:
    """Может ли actor все, что может цель (учетка или машина).

    Действовать за другого (задать ему пароль, выпустить машине секрет) можно
    только тому, кто и сам может все, что она. Проверять одну точку на
    политику мало: запрет актора на папку внутри разрешения цели так не виден,
    и ответственный без права на /private входил туда через разработчика.
    Поэтому решение сравнивается во всех местах, где оно может меняться:
    проекты и окружения из политик обоих, пути из политик обоих.

    И во все моменты, когда чья-то политика кончается: право, которое у
    актора кончится раньше, чем у цели, цель не покрывает. Иначе временный
    ответственный получал через сброс пароля или новый секрет машины доступ
    без срока.
    """
    if actor.role == OWNER:
        return True
    pairs = {(p.project_id, p.environment_id) for p in [*actor_policies, *target_policies]}
    paths = interesting_paths([*actor_policies, *target_policies], [])
    # Покрытие может сломаться, только когда актор теряет разрешение или цель
    # теряет запрет: остальные сроки проверять незачем, а каждый момент - это
    # полный перебор мест и действий.
    turning = [p for p in actor_policies if p.effect == "allow"] + [
        p for p in target_policies if p.effect == "deny"
    ]
    for at in moments(now, turning):
        for project_id, env_id in pairs:
            for path in paths:
                scope = Scope(project_id=project_id, environment_id=env_id, path=path)
                for action in actions:
                    if target_decide(action, scope, at) and not decide(actor_policies, actor, action, scope, at):
                        return False
    return True


async def visible_projects(session: AsyncSession, user: User) -> set[int] | None:
    """Проекты, которые человеку вообще видно. None = все (владелец).

    Пустое множество - нормальное состояние новой учетки: прав еще не выдали, и
    панель должна честно показать пустой список, а не список чужих проектов с
    отказом на каждом клике.
    """
    if user.role == OWNER:
        return None
    now = datetime.now(timezone.utc)
    policies = await policies_for(session, user)
    out: set[int] = set()
    everything = False
    for policy in policies:
        if not alive(policy, now) or policy.effect != "allow":
            continue
        if policy.require_2fa and not user.totp_enabled:
            continue
        if LIST not in policy_actions(policy) and READ not in policy_actions(policy):
            continue
        if policy.project_id is None:
            everything = True
        else:
            out.add(policy.project_id)
    # Запрет на проект целиком (без окружения, с корня) убирает его из списка:
    # при общем разрешении он оставался со всеми окружениями, хотя открыть его
    # было нельзя.
    hidden = {
        p.project_id
        for p in policies
        if p.effect == "deny"
        and alive(p, now)
        and p.project_id is not None
        and p.environment_id is None
        and normalize_prefix(p.path_prefix or "/") == "/"
        and {LIST, READ} <= policy_actions(p)
    }
    if everything:
        if not hidden:
            return None
        return set(await session.scalars(select(Project.id))) - hidden
    return out - hidden
