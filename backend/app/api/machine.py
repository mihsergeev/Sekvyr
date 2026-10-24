"""Машинный контур: сервер забирает свои секреты и не может их испортить.

Это единственная часть панели, открытая наружу: ноды и сборки живут в сетях,
которых нет и не может быть в белом списке админов. Поэтому здесь другой вход
(машинная личность вместо учетки), другой срок токена (минуты) и -
принципиально - **нет маршрутов, которые пишут в секреты**.

Изменяющих маршрутов ровно четыре, и ни один не касается значений:

  * `POST /token` - обмен секрета на короткий токен;
  * `POST /report` - агент рассказывает о себе: версия, что применил;
  * `POST /revoke` - машина отзывает собственные токены;
  * `POST /enroll` - подключение сервера по одноразовому токену.

Список повторен в `ops/selfcheck.py`: если в этом файле появится пятый
изменяющий маршрут, сборка упадет. Правило, которое держится глазами, рано или
поздно не удержится.
"""

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from app import access, audit, e2e, kube, machines, ratelimit, roles, secrets_store
from app.config import get_settings
from app.db import bump_token_version
from app.deps import SessionDep, UnsealedBox, peer_ip
from app.models import (
    ProjectKeyWrap,
    Cluster,
    EnrollToken,
    Environment,
    MachineApp,
    MachineIdentity,
    MachineRead,
    Policy,
    Project,
    Secret,
    User,
)
from app.security import hash_token

router = APIRouter(prefix="/v1/machine", tags=["machine"])

bearer = HTTPBearer(auto_error=False)


# Управляющие C0 и C1, переворот строки и символы нулевой ширины. Имя хоста и
# идентификатор приходят сюда до проверки токена, а отчет - от самой машины, и
# все это попадает в журнал и в список серверов. С такими символами строка там
# выглядит как другая, а перевод строки рисует в выгрузке журнала лишнюю запись.
_UNSEEN = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)


def _plain(text: str, limit: int) -> str:
    """Строка от машины, пригодная для журнала и интерфейса: без невидимого и не
    длиннее limit."""
    return _UNSEEN.sub("", text).strip()[:limit]


# --- вход -----------------------------------------------------------------


class TokenIn(BaseModel):
    """Вход машины. Либо пара "идентификатор + секрет", либо токен кластера.

    Один маршрут на оба способа намеренно: точка входа в машинный контур должна
    быть одна, и список изменяющих маршрутов в нем не должен расти от каждого
    нового способа доказать, кто ты.
    """

    client_id: str = Field(default="", max_length=64)
    client_secret: str = Field(default="", max_length=200)
    # projected-токен ServiceAccount: под читает его из
    # /var/run/secrets/kubernetes.io/serviceaccount/token
    kubernetes_token: str = Field(default="", max_length=8000)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    name: str


class WhoamiOut(BaseModel):
    name: str
    client_id: str
    environments: list[str] = []
    expires_at: str = ""


class ValueOut(BaseModel):
    name: str
    path: str
    value: str


class ProjectKeyOut(BaseModel):
    """Ключ e2e-проекта, запечатанный на публичный ключ этой машины.

    Панель раскрыть его не может: она хранит то, что запечатал браузер.
    """

    nonce: str
    wrapped_key: str
    ephemeral_public: str


class SecretsOut(BaseModel):
    project: str
    environment: str
    values: list[ValueOut]
    # Заполнено только у проекта с шифрованием в браузере: без этой обертки
    # значения останутся для агента непрозрачными блобами.
    e2e: bool = False
    project_key: ProjectKeyOut | None = None


class EnvFileOut(BaseModel):
    project: str
    environment: str
    text: str


class ReportIn(BaseModel):
    agent_version: str = Field(default="", max_length=64)
    applied: str = Field(default="", max_length=200)
    # Про какое приложение отчет. Агент на сервере один, приложений у него
    # список, и без этих полей панель знала бы только про последнее из них.
    project: str = Field(default="", max_length=64)
    env: str = Field(default="", max_length=64)
    group: str = Field(default="", max_length=64)
    # Файл, который агент поддерживает. Не секрет: путь, а не содержимое.
    # Длинный путь обрезается, а не роняет отчет целиком: с 422 пропадали и
    # версия агента, и ключ ноды.
    path: str = Field(default="", max_length=4096)
    # Публичный ключ ноды (ECDH P-256): им человек запечатывает ключ
    # e2e-проекта. Приватная половина остается на ноде и панели не
    # показывается никогда.
    public_key: str = Field(default="", max_length=200)
    # Что за система на сервере и каким адресом он виден во внутренней сети.
    # Ни то, ни другое панель по соединению узнать не может, а в списке серверов
    # это первое, о чем спрашивают.
    os: str = Field(default="", max_length=128)
    local_ip: str = Field(default="", max_length=64)


async def current_machine(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: SessionDep,
) -> MachineIdentity:
    """Машина по её короткому токену.

    Проверяется все то же, что у человека, плюс адрес: у машинной личности он
    обычно известен заранее, и белый список - самая дешевая защита от утекшего
    из лога сборки токена.
    """
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Недействительный или отсутствующий токен"
    )
    if credentials is None:
        # HTTPBearer молча отдает None на все, что не Bearer, поэтому basic
        # читаем из заголовка сами - иначе внешние интеграции получали бы 401
        # без объяснимой причины.
        raw = request.headers.get("authorization", "")
        scheme, _, value = raw.partition(" ")
        if scheme.lower() != "basic" or not value:
            raise unauthorized
        return await _machine_by_basic(session, value.strip(), peer_ip(request))
    if credentials.scheme.lower() == "basic":
        # Пара "идентификатор + секрет" прямо в запросе. Так умеют внешние
        # интеграции вроде External Secrets Operator: два шага (сначала токен,
        # потом чтение) они не делают. Секрет при этом тот же самый, что лежал
        # бы у них в Secret'е кластера, и ездит он только по TLS.
        return await _machine_by_basic(session, credentials.credentials, peer_ip(request))
    payload = machines.decode_token(credentials.credentials, get_settings().jwt_secret)
    if payload is None:
        raise unauthorized
    machine = await session.get(MachineIdentity, payload.get("mid", 0))
    if machine is None or not machines.alive(machine):
        raise unauthorized
    # Номер машины - не вся личность: под тем же номером может жить уже другая
    # машина (удалили и завели новую), и токен прежней не должен ей подходить.
    if payload.get("sub") != machines.token_subject(machine):
        raise unauthorized
    if payload.get("ver", 0) != machine.token_version:
        raise unauthorized
    if not machines.ip_allowed(machine.allow_ips, peer_ip(request)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Адрес не в белом списке личности")
    return machine


async def _machine_by_basic(session: SessionDep, encoded: str, ip: str) -> MachineIdentity:
    """Личность по basic-паре. Отдельно от токена: здесь нет ни версии токена,
    ни срока - только сам секрет, и проверять его надо каждый раз.

    Отказ - как у /token: в журнал и в лимитер. Утекшая пара с чужого адреса
    иначе получала молчаливый 401, и в журнале не было ни следа."""
    try:
        raw = base64.b64decode(encoded).decode()
    except (ValueError, UnicodeDecodeError):
        raw = ""
    client_id, _, secret = raw.partition(":")
    machine = None
    if client_id:
        machine = await session.scalar(
            select(MachineIdentity).where(MachineIdentity.client_id == client_id)
        )
    ok = (
        machine is not None
        and bool(secret)
        and bool(machine.secret_hash)
        and hmac.compare_digest(machine.secret_hash, hash_token(secret))
        and machines.alive(machine)
        and machines.ip_allowed(machine.allow_ips, ip)
    )
    if not ok or machine is None:
        await _deny(
            session, machine, client_id or "basic", ip, "basic",
            "Недействительный или отсутствующий токен",
        )
    return machine


async def _deny(
    session: SessionDep,
    machine: MachineIdentity | None,
    label: str,
    ip: str,
    target: str,
    message: str,
) -> None:
    """Отказ машине: журнал и лимитер.

    Неизвестной машине - лимитер по адресу (у IPv6 по сети /64) и строка
    журнала на каждый отказ. Известной - строка журнала раз в час на причину,
    без лимитера: секрет не подобрать, а ESO с выключенной машиной спрашивает
    раз в 15 секунд и засыпал журнал тысячами строк в сутки, получая вдобавок
    429 вместо настоящей причины.
    """
    if machine is not None:
        # По client_id, а не по номеру: номер удаленной машины достается
        # новой, и ее первый отказ иначе молча пропадал бы.
        quiet = (machine.client_id, target)
        now = datetime.now(timezone.utc)
        last = _REFUSED_LOGGED.get(quiet)
        if last is None or now - last >= DENIED_QUIET:
            _REFUSED_LOGGED[quiet] = now
            await audit.record(
                session,
                actor=f"machine:{_plain(label, 64)}",
                action="machine_denied",
                target=target,
                ip=ip,
            )
            await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, message)
    key = f"machine:{ratelimit.subject(ip)}"
    if await ratelimit.is_locked(session, key):
        # Порог уже пройден и записан: новые строки журнала ничего не
        # добавят, а засыпать его отказами можно было бы без конца.
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Слишком много попыток — повторите позже"
        )
    await ratelimit.record_failure(session, key)
    # Одинаковый ответ на "нет такой личности", "неверный секрет" и "не тот
    # адрес": разница подсказывала бы, какой из трех параметров угадан.
    await audit.record(
        session,
        actor=f"machine:{_plain(label, 64)}",
        action="machine_denied",
        target=target,
        ip=ip,
    )
    await session.commit()
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, message)


CurrentMachine = Annotated[MachineIdentity, Depends(current_machine)]


async def _machine_by_kubernetes(
    session: SessionDep, token: str, ip: str
) -> tuple[MachineIdentity | None, bool]:
    """Личность за подом: namespace и имя ServiceAccount из проверенного токена.

    Кластеры перебираем: их единицы, а издатель у ванильного кластера
    (`kubernetes/serviceaccount`) одинаков у всех, и выбрать "тот самый" по
    заголовку токена нельзя.
    """
    clusters = list(await session.scalars(select(Cluster).where(Cluster.disabled.is_(False))))
    for cluster in clusters:
        try:
            namespace, account = kube.verify(
                token,
                jwks_text=cluster.jwks,
                issuer=cluster.issuer,
                audience=cluster.audience,
            )
        except kube.TokenError:
            continue
        machine = await session.scalar(
            select(MachineIdentity)
            .where(
                MachineIdentity.cluster_id == cluster.id,
                MachineIdentity.k8s_namespace == namespace,
                MachineIdentity.k8s_service_account == account,
            )
            .order_by(MachineIdentity.id)
            .limit(1)
        )
        if machine is None:
            continue
        return machine, machines.alive(machine) and machines.ip_allowed(machine.allow_ips, ip)
    return None, False


KEY_CHANGED = "ключ ноды сменился, выданные этой машине ключи проектов сняты"


async def _creator_still_may(
    session: SessionDep, token: EnrollToken
) -> tuple[bool, datetime | None]:
    """Токен действует правами того, кто его выписал, - на момент подключения.

    Выписанный и неиспользованный токен иначе переживал права автора: учетку
    отключили или отняли у нее окружение, а сервер по ее токену еще до суток
    получал право читать это окружение целиком. Второе в ответе - до какого
    момента право автора держится: дольше него машина окружение не получает.
    """
    creator = await session.scalar(select(User).where(User.username == token.created_by))
    if creator is None or creator.disabled:
        return False, None
    # Выписывает токены ответственный и выше; пониженный автор новый выписать
    # уже не может, и старый действовать не должен.
    if roles.level(creator.role) < roles.level(roles.MAINTAINER):
        return False, None
    if token.environment_id is None:
        return True, None
    environment = await session.get(Environment, token.environment_id)
    if environment is None:
        return True, None
    paths = await secrets_store.env_paths(session, environment.id)
    return await access.whole_until(
        session, creator, access.READ, environment.project_id, environment.id, paths
    )


KEEPER_GONE = "Тот, кто завел машину или ее кластер, больше не может выдавать ей доступ"


async def _keepers_still_may(session: SessionDep, machine: MachineIdentity) -> bool:
    """Токен машине - пока тот, кто ее завел, может заводить машины, а у машины
    за подом - и тот, кто завел ее кластер. Та же проверка, что у токена
    подключения (_creator_still_may): у отключенного человека остается секрет
    его машины, и без этой проверки он читал бы через нее то, что ему уже
    закрыто.
    Чтение проверяет то же самое и вдобавок каждое выданное право
    (machines.effective_policies): уже выданный токен живет четверть часа."""
    names = [machine.created_by]
    if machine.cluster_id is not None:
        cluster = await session.get(Cluster, machine.cluster_id)
        names.append(cluster.created_by if cluster else "")
    for name in names:
        keeper = await session.scalar(select(User).where(User.username == name))
        if not machines.may_vouch(keeper):
            return False
    return True


@router.post("/token", response_model=TokenOut)
async def issue_token(
    body: TokenIn, request: Request, session: SessionDep
) -> TokenOut:
    """Обмен секрета на короткий токен.

    Секрет машины - 288 случайных бит, подобрать его нельзя, поэтому лимитер
    здесь не стена, а глушитель: он не дает отказам засыпать журнал. И
    срабатывает он только на отказы. Верная пара проходит всегда: иначе одна
    удаленная или выключенная машина с живым агентом за общим адресом (поды
    за SNAT, офис) запирала бы выдачу токенов всем соседям, и новые поды не
    поднимались бы. Отказы известной машины считаются на нее саму, неизвестной -
    на адрес, а у IPv6 на его сеть /64.
    """
    ip = peer_ip(request)
    machine: MachineIdentity | None = None
    ok = False
    if body.kubernetes_token:
        machine, ok = await _machine_by_kubernetes(session, body.kubernetes_token, ip)
    elif body.client_id:
        machine = await session.scalar(
            select(MachineIdentity).where(MachineIdentity.client_id == body.client_id)
        )
        ok = (
            machine is not None
            # У личности с ServiceAccount секрета нет вовсе: пустой хеш не должен
            # совпадать ни с чем, иначе "без секрета" превратилось бы в "любой".
            and bool(machine.secret_hash)
            and machines.alive(machine)
            and hmac.compare_digest(machine.secret_hash, hash_token(body.client_secret))
            and machines.ip_allowed(machine.allow_ips, ip)
        )
    if not ok or machine is None:
        await _deny(
            session, machine, body.client_id or "kubernetes", ip, "token",
            "Неверная пара идентификатор и секрет",
        )
    if not await _keepers_still_may(session, machine):
        await _deny(
            session, machine, body.client_id or "kubernetes", ip, "token",
            KEEPER_GONE,
        )

    token, ttl = machines.create_token(machine, get_settings().jwt_secret)
    # Удачная выдача в журнал не пишется: агент берет токен на каждый круг, то
    # есть каждую минуту, и журнал зарастал этими строками. Сам токен значений
    # не открывает, их открывает чтение, а оно в журнал попадает, в том числе с
    # каждого нового адреса. Отказы пишутся всегда, они выше.
    machine.last_seen_at = datetime.now(timezone.utc)
    machine.last_ip = ip
    await session.commit()
    return TokenOut(access_token=token, expires_in=ttl, name=machine.name)


# --- чтение ---------------------------------------------------------------


# Когда последний раз писали отказ машине в журнал (см. _guard).
_DENIED_LOGGED: dict[tuple[int, int], datetime] = {}
DENIED_QUIET = timedelta(hours=1)
# То же для отказа во входе известной машине (см. _deny).
_REFUSED_LOGGED: dict[tuple[str, str], datetime] = {}


async def _resolve(
    session: SessionDep, machine: MachineIdentity, project: str, env: str, group: str
) -> tuple[Project, Environment]:
    """Проект и окружение по именам, а не по номерам.

    Номера у разных стендов свои, а конфиг агента переезжает между ними как
    есть. Имя группы можно не указывать, пока имя проекта во всей панели
    единственное.

    Адрес из конфига агента подменять нельзя: ответ с чужим проектом агент
    молча запишет в .env и перезапустит приложение. Поэтому проект берется
    либо ровно по адресу, либо тот, что переехал с этого адреса в другую
    группу, и никогда - просто одноименный, оказавшийся выданным.
    """
    # Кандидаты - только то, что этой машине выдано: ответы "нет такого",
    # "не выдано" и "есть в нескольких группах" иначе перечисляли бы чужие
    # проекты и окружения по именам. На все чужое ответ один.
    candidates: list[tuple[Project, Environment]] = []
    rows = await session.execute(
        select(Project, Environment)
        .join(Environment, Environment.project_id == Project.id)
        .where(Project.slug == project, Environment.name == env)
    )
    for found, environment in rows:
        if await machines.sees_anything(
            session, machine, access.READ, found.id, environment.id
        ) or await machines.sees_anything(session, machine, access.LIST, found.id, environment.id):
            candidates.append((found, environment))
    exact = [pair for pair in candidates if pair[0].group_slug == group]
    if exact:
        candidates = exact
    elif candidates:
        here = await session.scalar(
            select(Project.id)
            .where(Project.group_slug == group, Project.slug == project)
            .limit(1)
        )
        # Проект по этому адресу есть, но машине его не выдали или право
        # кончилось: отказ, а не тезка из соседней группы.
        moved = [
            pair for pair in candidates if (group or "-") in pair[0].moved_from.split()
        ]
        if here is not None:
            candidates = []
        elif len(moved) == 1:
            # Проект перенесли в другую группу, а агент помнит прежнюю. Без
            # этого перенос молча отключал все подключенные серверы, поды и ESO.
            candidates = moved
        elif group:
            candidates = []
        else:
            # Без группы проект ищется по одному имени, и оно должно быть
            # единственным во всей панели, а не только среди выданного: иначе
            # потеря права на свой проект переключала бы сервер на тезку.
            # Что тезка где-то есть, машина узнает, но не узнает, где именно.
            namesakes = await session.scalar(
                select(func.count()).select_from(Project).where(Project.slug == project)
            )
            if namesakes > 1:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Проект с таким именем есть в нескольких группах — укажите group",
                )
    if len(candidates) > 1:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Проект с таким именем есть в нескольких группах — укажите group",
        )
    if not candidates:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Этой машине окружение не выдано")
    return candidates[0]


async def _guard(
    session: SessionDep,
    machine: MachineIdentity,
    environment: Environment,
    request: Request,
    action: str = access.READ,
) -> None:
    # Хоть одна папка: машинная политика только на /app раньше не давала
    # ничего. Что именно отдать, решается дальше по каждому пути.
    if await machines.sees_anything(session, machine, action, environment.project_id, environment.id):
        return
    # Отказ пишется в журнал раз в час на машину и окружение: агент, у которого
    # сняли окружение, спрашивает каждую минуту, и журнал заполнялся бы одной
    # и той же строкой.
    key = (machine.id, environment.id)
    now = datetime.now(timezone.utc)
    last = _DENIED_LOGGED.get(key)
    if last is not None and now - last < DENIED_QUIET:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Этой машине окружение не выдано")
    _DENIED_LOGGED[key] = now
    await audit.record(
        session,
        actor=f"machine:{machine.client_id}",
        action="machine_denied",
        target=str(environment.id),
        ip=peer_ip(request),
    )
    await session.commit()
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Этой машине окружение не выдано")


# Как долго повторное чтение того же набора с известного адреса не попадает в
# журнал. Сутки: по журналу видно каждый день, в который машина читала
# окружение, и при этом с сервера приходит одна строка в день, а не полторы
# тысячи.
READ_QUIET = timedelta(days=1)
# Сколько последних адресов помнить на окружение. Хватает на кластер, поды
# которого выходят наружу с разных нод, и не дает строке расти без конца.
READ_IPS = 8


def _fingerprint(secrets: list[Secret]) -> str:
    """Отпечаток набора по номерам версий. Значения в нем не участвуют."""
    parts = sorted(f"{secret.id}:{secret.current_version}" for secret in secrets)
    return hashlib.sha256(" ".join(parts).encode()).hexdigest()


async def _record_read(
    session: SessionDep,
    machine: MachineIdentity,
    environment: Environment,
    *,
    target: str,
    detail: str,
    ip: str,
    fingerprint: str,
) -> None:
    """Чтение машиной в журнал, без повторов.

    Строка появляется, когда машина получает другой набор значений, приходит
    за этим набором с нового адреса или когда с прошлой строки прошли сутки.
    Повторы между строками считаются, и их число попадает в следующую.
    """
    now = datetime.now(timezone.utc)
    key = (machine.id, environment.id)
    seen = await session.get(MachineRead, key)
    if seen is not None:
        known = seen.ips.split()
        if (
            seen.fingerprint == fingerprint
            and ip in known
            and now - audit.to_utc(seen.recorded_at) < READ_QUIET
        ):
            seen.repeats += 1
            return
        if seen.repeats:
            detail += f", повторных чтений с прошлой записи: {seen.repeats}"
    await audit.record(
        session,
        actor=f"machine:{machine.client_id}",
        action="machine_read",
        target=target,
        detail=detail,
        ip=ip,
    )
    if seen is None:
        # Журнал пишется под общей блокировкой, и она уже взята: если
        # параллельный запрос той же машины успел завести строку, она теперь
        # видна, и вторая вставка не упадет на первичном ключе.
        seen = await session.get(MachineRead, key)
    if seen is None:
        seen = MachineRead(machine_id=machine.id, environment_id=environment.id, ips="")
        session.add(seen)
        known = []
    else:
        known = seen.ips.split() if seen.fingerprint == fingerprint else []
    seen.ips = " ".join([ip] + [x for x in known if x != ip][: READ_IPS - 1])
    seen.fingerprint = fingerprint
    seen.recorded_at = now
    seen.repeats = 0


@router.get("/whoami", response_model=WhoamiOut)
async def whoami(machine: CurrentMachine, session: SessionDep) -> WhoamiOut:
    """Кто я и что мне выдано. Первое, что спрашивает агент после настройки."""
    names: list[str] = []
    for policy in await machines.effective_policies(session, machine):
        if policy.effect != "allow" or policy.environment_id is None:
            continue
        environment = await session.get(Environment, policy.environment_id)
        if environment is None:
            continue
        project = await session.get(Project, environment.project_id)
        if project is None:
            names.append(environment.name)
            continue
        group = f"{project.group_slug}/" if project.group_slug else ""
        names.append(f"{group}{project.slug}/{environment.name}")
    return WhoamiOut(
        name=machine.name,
        client_id=machine.client_id,
        environments=sorted(set(names)),
        expires_at=machine.expires_at.isoformat() if machine.expires_at else "",
    )


@router.get("/secrets", response_model=SecretsOut)
async def read_secrets(
    request: Request,
    machine: CurrentMachine,
    session: SessionDep,
    box: UnsealedBox,
    project: str = Query(min_length=1, max_length=64),
    env: str = Query(min_length=1, max_length=64),
    group: str = Query(default="", max_length=64),
) -> SecretsOut:
    """Значения окружения - включая унаследованные от родителя.

    Именно включая: агенту нужен рабочий набор, а не список того, что задано
    именно здесь.
    """
    found, environment = await _resolve(session, machine, project, env, group)
    await _guard(session, machine, environment, request)

    values: list[ValueOut] = []
    # Запрет на папку в машинной политике действует и здесь: раньше машина
    # получала окружение целиком.
    can_read = await machines.place_check(
        session, machine, access.READ, environment.project_id, environment.id
    )
    effective = secrets_store.one_per_name(
        [
            secret
            for secret, _level in await secrets_store.effective_list(session, environment.id)
            if can_read(secret.path)
        ]
    )
    # Пачкой: по ключу за раз это два запроса и расшифровка на каждый ключ, и
    # окружение на 5000 ключей отдавалось агенту 5-6 с, а шесть агентов разом
    # упирались в его таймаут.
    plain = await secrets_store.values_of(
        session, box, environment.id, only={secret.id for secret in effective}
    )
    for secret in effective:
        value = plain.get((secret.path, secret.name))
        if value is None:
            continue
        values.append(ValueOut(name=secret.name, path=secret.path, value=value))
    project_key = None
    if found.e2e:
        wrap = await session.scalar(
            select(ProjectKeyWrap).where(
                ProjectKeyWrap.project_id == found.id,
                ProjectKeyWrap.subject_type == "machine",
                ProjectKeyWrap.subject_id == machine.id,
            )
        )
        if wrap is None:
            # Без обертки агент получил бы непрозрачные блобы и молча положил
            # их в файл. Лучше честный отказ с понятной причиной.
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Ключ проекта этой машине не выдан: откройте проект в панели и "
                "выдайте ей ключ",
            )
        parts = wrap.wrapped_key.split("\x1f")
        project_key = ProjectKeyOut(
            nonce=wrap.nonce,
            wrapped_key=parts[0],
            ephemeral_public=parts[1] if len(parts) > 1 else "",
        )

    machine.last_seen_at = datetime.now(timezone.utc)
    machine.last_ip = peer_ip(request)
    await _record_read(
        session,
        machine,
        environment,
        target=f"{found.slug}/{environment.name}",
        detail=f"ключей: {len(values)}",
        ip=peer_ip(request),
        fingerprint=_fingerprint(effective),
    )
    await session.commit()
    return SecretsOut(
        project=found.slug,
        environment=environment.name,
        values=values,
        e2e=found.e2e,
        project_key=project_key,
    )


@router.get("/env", response_model=EnvFileOut)
async def read_env_file(
    request: Request,
    machine: CurrentMachine,
    session: SessionDep,
    box: UnsealedBox,
    project: str = Query(min_length=1, max_length=64),
    env: str = Query(min_length=1, max_length=64),
    group: str = Query(default="", max_length=64),
) -> EnvFileOut:
    """То же самое готовым файлом .env - чтобы агенту не пришлось собирать его
    самому и заново решать, что и как экранировать."""
    found, environment = await _resolve(session, machine, project, env, group)
    await _guard(session, machine, environment, request)
    if found.e2e:
        # Файл собирает тот, у кого есть ключ проекта, - то есть агент у себя.
        # Сервер сложить его не может и делать вид, что может, не должен.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "У проекта шифрование в браузере: файл собирает агент из значений, "
            "полученных запросом /secrets",
        )
    can_read = await machines.place_check(
        session, machine, access.READ, environment.project_id, environment.id
    )
    text = await secrets_store.export_env(
        session, box, environment.id, keep=can_read, for_machine=True
    )
    effective = secrets_store.one_per_name(
        [
            secret
            for secret, _level in await secrets_store.effective_list(session, environment.id)
            if can_read(secret.path)
        ]
    )
    machine.last_seen_at = datetime.now(timezone.utc)
    machine.last_ip = peer_ip(request)
    await _record_read(
        session,
        machine,
        environment,
        target=f"{found.slug}/{environment.name}",
        detail="файл .env",
        ip=peer_ip(request),
        fingerprint=_fingerprint(effective),
    )
    await session.commit()
    return EnvFileOut(project=found.slug, environment=environment.name, text=text)


# --- о себе ---------------------------------------------------------------


async def _remember_app(
    session: SessionDep, machine: MachineIdentity, body: "ReportIn"
) -> bool:
    """Запомнить, что это приложение живет на этой машине. Возвращает, поменялось
    ли что-то, кроме времени: новое приложение, другой файл или другой итог.

    Записываем только то, что машине действительно выдано: отчет приходит от
    нее самой, и на слово ей верить незачем - иначе своей строкой она могла бы
    объявиться на странице чужого окружения. Незнакомое или невыданное
    приложение пропускаем молча: отчет не должен падать из-за строки, оставшейся
    в конфиге от прошлой жизни сервера.
    """
    if not body.project or not body.env:
        return False
    try:
        found, environment = await _resolve(session, machine, body.project, body.env, body.group)
    except HTTPException:
        return False
    # Машине бывает выдана одна папка: проверка по корню не заводила строку
    # приложения, хотя значения машина получала.
    if not await machines.sees_anything(
        session, machine, access.READ, environment.project_id, environment.id
    ):
        return False
    row = await session.scalar(
        select(MachineApp).where(
            MachineApp.machine_id == machine.id,
            MachineApp.group_slug == found.group_slug,
            MachineApp.project_slug == found.slug,
            MachineApp.env_name == environment.name,
        )
    )
    if row is None:
        row = MachineApp(
            machine_id=machine.id,
            group_slug=found.group_slug,
            project_slug=found.slug,
            env_name=environment.name,
        )
        # Поды одной личности отчитываются одновременно, и первый отчет двух
        # подов мог упасть на уникальности строки с 500. Вставка - в своей
        # точке сохранения: проиграл гонку - берем строку победителя.
        try:
            async with session.begin_nested():
                session.add(row)
        except IntegrityError:
            row = await session.scalar(
                select(MachineApp).where(
                    MachineApp.machine_id == machine.id,
                    MachineApp.group_slug == found.group_slug,
                    MachineApp.project_slug == found.slug,
                    MachineApp.env_name == environment.name,
                )
            )
            if row is None:
                return False
    path, applied = _plain(body.path, 300), _plain(body.applied, 200)
    changed = row.path != path or row.applied != applied
    row.path = path
    row.applied = applied
    row.last_seen_at = datetime.now(timezone.utc)
    return changed


@router.post("/report")
async def report(
    body: ReportIn, request: Request, machine: CurrentMachine, session: SessionDep
) -> dict[str, str]:
    """Агент рассказывает о себе: версия и что он применил.

    Ничего, кроме собственной карточки, этот маршрут не трогает - в панели по
    нему видно, доехала ли правка до сервера, а не только то, что она сохранена.

    Отчет приходит каждую минуту, а в журнал попадает, только когда что-то
    поменялось: версия агента, ключ ноды или то, что приложение применило.
    Система и внутренний адрес в это не входят: у подов одной личности они
    разные, и каждое чередование давало бы строку.
    """
    before = (machine.agent_version, machine.public_key)
    version, applied = _plain(body.agent_version, 64), _plain(body.applied, 200)
    machine.agent_version = version
    # Отчет без итога (агент жив, а значений этот раз не было: e2e-проект без
    # ключа, отказ, файл не записан) не затирает прежний итог.
    if applied:
        machine.applied = applied
    machine.last_seen_at = datetime.now(timezone.utc)
    machine.last_ip = peer_ip(request)
    # Пустое поле не затирает известное: старый агент про систему молчит, и
    # терять из-за этого то, что панель уже показывала, незачем.
    system, local_ip = _plain(body.os, 128), _plain(body.local_ip, 64)
    if system:
        machine.os = system
    if local_ip:
        machine.local_ip = local_ip
    key_changed = bool(machine.public_key) and bool(body.public_key) and (
        body.public_key != machine.public_key
    )
    if body.public_key and body.public_key != machine.public_key:
        # Ключ ноды нужен, чтобы человек мог запечатать на него ключ
        # e2e-проекта. Смена ключа гасит прежние обертки: они больше не
        # раскроются, и это правильнее, чем оставить их выглядеть рабочими.
        try:
            e2e.check_public_key(body.public_key)
        except e2e.FormatError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        machine.public_key = body.public_key
        await session.execute(
            delete(ProjectKeyWrap).where(
                ProjectKeyWrap.subject_type == "machine",
                ProjectKeyWrap.subject_id == machine.id,
            )
        )
    app_changed = await _remember_app(session, machine, body)
    if app_changed or before != (machine.agent_version, machine.public_key):
        # Смена ключа ноды названа в журнале отдельно. Ее же видит и тот, кто
        # украл секрет машины и прислал свой ключ: следующая "Выдать заново"
        # отдала бы ему ключ проекта. Прежде чем выдавать, стоит понять, почему
        # ключ сменился (переустановка ноды - да, на ровном месте - нет).
        parts = [f"{version} {applied}".strip()]
        if key_changed:
            parts.append(KEY_CHANGED)
        await audit.record(
            session,
            actor=f"machine:{machine.client_id}",
            action="machine_reported",
            target=machine.name,
            detail="; ".join(part for part in parts if part),
            ip=peer_ip(request),
        )
    await session.commit()
    return {"detail": "принято"}


@router.post("/revoke")
async def revoke_own_tokens(
    request: Request, machine: CurrentMachine, session: SessionDep
) -> dict[str, str]:
    """Машина отзывает собственные токены - например, заметив утечку в логе.

    Секрет при этом остается рабочим: машина возьмет новый токен и продолжит
    работать, а старые перестанут действовать немедленно.
    """
    await bump_token_version(session, machine)
    await audit.record(
        session,
        actor=f"machine:{machine.client_id}",
        action="machine_revoked",
        target=machine.name,
        ip=peer_ip(request),
    )
    await session.commit()
    return {"detail": "токены отозваны"}


# --- подключение сервера --------------------------------------------------


class EnrollIn(BaseModel):
    token: str = Field(min_length=8, max_length=200)
    hostname: str = Field(default="", max_length=120)
    agent_version: str = Field(default="", max_length=64)


class EnrollOut(BaseModel):
    name: str
    client_id: str
    client_secret: str
    project: str = ""
    group: str = ""
    env: str = ""


@router.post("/enroll", response_model=EnrollOut)
async def enroll(body: EnrollIn, request: Request, session: SessionDep) -> EnrollOut:
    """Одноразовый токен в обмен на постоянную машинную личность.

    Единственный маршрут контура, который заводит что-то новое - и он не
    касается значений: заводится личность и, если токен так выписан, право на
    чтение одного окружения. Здесь же токен помечается использованным: второй
    сервер по нему уже не подключится.
    """
    ip = peer_ip(request)
    key = f"enroll:{ratelimit.subject(ip)}"
    if await ratelimit.is_locked(session, key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Слишком много попыток — повторите позже"
        )

    now = datetime.now(timezone.utc)
    found = await session.scalar(
        select(EnrollToken).where(EnrollToken.token_hash == hash_token(body.token))
    )
    expires = found.expires_at if found else None
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    usable = (
        found is not None
        and found.used_at is None
        and expires is not None
        and expires > now
        # Адреса токена - это адреса будущей машины: с другого адреса она все
        # равно не получила бы значений, а токен, подсмотренный в ps на чужой
        # ноде, иначе гасился бы откуда угодно.
        and machines.ip_allowed(found.allow_ips, ip)
    )
    refused = ""
    until = None
    if usable:
        may, until = await _creator_still_may(session, found)
        if not may:
            usable = False
            refused = "создатель токена больше не может выдать это окружение"
    if usable:
        # Гасим токен условным UPDATE до всего остального: два одновременных
        # подключения с одним токеном иначе завели бы две личности.
        claimed = await session.execute(
            update(EnrollToken)
            .where(EnrollToken.id == found.id, EnrollToken.used_at.is_(None))
            .values(used_at=now)
            .execution_options(synchronize_session=False)
        )
        usable = claimed.rowcount == 1
    if not usable:
        await ratelimit.record_failure(session, key)
        await audit.record(
            session,
            actor="machine:?",
            action="machine_enroll_denied",
            target=_plain(body.hostname, 120),
            detail=refused,
            ip=ip,
        )
        await session.commit()
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Токен подключения недействителен или уже использован"
        )

    client_id, secret = machines.new_credentials()
    machine = MachineIdentity(
        name=_plain(body.hostname, 120) or client_id,
        client_id=client_id,
        secret_hash=hash_token(secret),
        description="",
        allow_ips=found.allow_ips,
        agent_version=_plain(body.agent_version, 64),
        last_seen_at=now,
        last_ip=ip,
        created_by=found.created_by,
    )
    session.add(machine)
    await session.flush()

    project = environment = None
    if found.environment_id is not None:
        environment = await session.get(Environment, found.environment_id)
        if environment is not None:
            project = await session.get(Project, environment.project_id)
            session.add(
                Policy(
                    subject_type="machine",
                    subject_id=machine.id,
                    project_id=environment.project_id,
                    environment_id=environment.id,
                    path_prefix="/",
                    actions=access.READ + "," + access.LIST,
                    effect="allow",
                    created_by=found.created_by,
                    expires_at=until,
                )
            )

    found.used_at = now
    found.used_by = machine.name
    await audit.record(
        session,
        actor=f"machine:{client_id}",
        action="machine_enrolled",
        target=machine.name,
        detail=(
            f"{project.slug}/{environment.name}"
            + (f" · до {until.isoformat(timespec='minutes')}" if until else "")
            if project and environment
            else ""
        ),
        ip=ip,
    )
    await session.commit()
    return EnrollOut(
        name=machine.name,
        client_id=client_id,
        client_secret=secret,
        project=project.slug if project else "",
        group=project.group_slug if project else "",
        env=environment.name if environment else "",
    )


# --- раздача агента -------------------------------------------------------

def _agent_dir() -> Path:
    """Где лежат бинари агента и подписанное описание версии.

    В образе это /srv/agent, но панель запускают и из исходников - тогда путь
    задают в SEKVYR_AGENT_DIR, иначе раздавать нечего.
    """
    return Path(get_settings().agent_dir)


def _manifest() -> dict:
    path = _agent_dir() / "manifest.json"
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Версия агента не подписана")
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/agent/manifest")
async def agent_manifest() -> dict:
    """Подписанное описание версии: что за версия и какие у бинарей хеши.

    Подпись делается ключом, которого на панели нет, и проверяет её сама нода.
    Панель здесь только почтальон: подменить бинарь она может, а подпись - нет.
    """
    return _manifest()


@router.get("/agent")
async def download_agent(arch: str = Query(default="amd64", max_length=16)) -> FileResponse:
    """Бинарь агента. Открыт без токена намеренно: сервер качает его до того,
    как у него появляется хоть какая-то личность, а сам бинарь секретов не
    содержит."""
    if arch not in {"amd64", "arm64"}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Нет сборки под эту архитектуру")
    path = _agent_dir() / f"sekvyr-linux-{arch}"
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Агент не собран в этом образе")
    # Раздаем только то, что описано подписью. Несовпадение означает, что в
    # образе лежит не тот бинарь, - и отдавать его нодам нельзя: они все равно
    # его отвергнут, но узнать об этом лучше здесь и сразу.
    expected = _manifest().get("files", {}).get(arch, {}).get("sha256", "")
    if expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Бинарь агента не совпадает с подписанным описанием",
        )
    return FileResponse(path, media_type="application/octet-stream", filename="sekvyr")


@router.get("/install.sh")
async def install_script(request: Request) -> PlainTextResponse:
    """Скрипт установки. Тоже без токена: его читает `sh` на чистой ноде, и
    ничего секретного в нем нет - весь доступ дает одноразовый токен, который
    человек подставляет сам."""
    path = _agent_dir() / "install.sh"
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Скрипт не собран в этом образе")
    text = path.read_text(encoding="utf-8")
    panel = get_settings().panel_url or str(request.base_url).rstrip("/")
    # Подставляем адрес панели, чтобы команду можно было копировать целиком.
    text = text.replace('PANEL="${SEKVYR_URL:-}"', f'PANEL="${{SEKVYR_URL:-{panel}}}"', 1)
    return PlainTextResponse(text, media_type="text/x-shellscript")
