"""Вход в панель и своя учетка.

Единственный маршрут без токена - вход. Он же единственный, куда можно долбить
подбором, поэтому у него счетчик попыток (app/ratelimit.py) и запись в журнал на
каждый исход: и на удачный, и на неудачный.
"""

import hashlib

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import alerts, audit, machines, ratelimit, roles, totp
from app.config import get_settings
from app.db import bump_token_version
from app.deps import CurrentUser, SessionDep, peer_ip
from app.models import User
from app.security import (
    MIN_PASSWORD_LEN,
    create_access_token,
    hash_password,
    hash_password_async,
    verify_password_async,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Заведомо недостижимый хеш: bcrypt от случайной строки. Нужен, чтобы проверка
# пароля занимала одно и то же время и когда учетки нет (см. login).
_DUMMY_HASH = hash_password("sekvyr-nonexistent-account-probe")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    # Код второго фактора. Пустой на первом шаге: панель ответит, что он нужен.
    otp: str = Field(default="", max_length=16)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MeOut(BaseModel):
    username: str
    role: str
    level: int
    role_title: str
    totp_enabled: bool = False


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=MIN_PASSWORD_LEN, max_length=256)


# Неудач по одному логину за окно лимитера, после которых владельцу сообщают о
# подборе. Запирать саму учетку нельзя: так любой снаружи запирал бы вход
# владельцу. Адреса меняются, а логин остается, поэтому считаем и его.
ACCOUNT_ALERT = 30

TOO_MANY = "Слишком много попыток — повторите позже"
TOO_MANY_LOGINS = "Слишком много попыток входа — повторите позже"

# Неверных кодов второго фактора за окно лимитера - на учетку, а не на адрес.
# До кода доходит только тот, кто знает пароль, а адресов у него может быть
# сколько угодно: по адресу код подбирался бы без конца. Запереть так вход
# владельцу может лишь знающий пароль, и об этом сразу сообщается.
OTP_LIMIT = 5


def _account_key(username: str) -> str:
    return "user:" + hashlib.sha256(username.lower().encode()).hexdigest()[:40]


async def _login_failed(
    session, attempt: ratelimit.Attempt, username: str, ip: str, detail: str = ""
) -> None:
    # Неудача с адреса уже в счете: попытка записана до проверки пароля.
    locked_now = attempt.closes
    account_now = await ratelimit.record_failure(
        session, _account_key(username), limit=ACCOUNT_ALERT
    )
    await audit.record(
        session,
        actor=username,
        action="login_failed",
        ip=ip,
        detail="порог попыток достигнут" if locked_now else detail,
    )
    await session.commit()
    if locked_now:
        # Ровно один раз на блокировку, а не на каждую следующую попытку:
        # поток одинаковых сообщений выключают, а вместе с ним - и все
        # остальные оповещения панели.
        await alerts.notify(
            session,
            f"🚨 Sekvyr: вход с адреса {ip} заблокирован после серии неудачных "
            f"попыток (последний логин — «{username}»)",
        )
    if account_now:
        await alerts.notify(
            session,
            f"🚨 Sekvyr: к учетной записи «{username}» подбирают пароль: "
            f"{ACCOUNT_ALERT} неудачных попыток за {ratelimit.WINDOW // 60} минут",
        )


async def consume_totp(session, user: User, code: str) -> bool:
    """Код второго фактора подошел, и его окно теперь использовано.

    Окно отмечается условным UPDATE, а не присваиванием: два одновременных
    запроса с одним кодом иначе прошли бы оба, и одноразовый код работал бы
    дважды."""
    counter = totp.verify(user.totp_secret, code, last_counter=user.totp_last_counter)
    if counter is None:
        return False
    # Секрет - тот, по которому код проверен: параллельный /2fa/start мог его
    # сменить, и включение фактора с секретом, которого у человека нет,
    # запирало учетку.
    done = await session.execute(
        update(User)
        .where(
            User.id == user.id,
            User.totp_last_counter < counter,
            User.totp_secret == user.totp_secret,
        )
        .values(totp_last_counter=counter)
        .execution_options(synchronize_session=False)
    )
    if done.rowcount != 1:
        return False
    user.totp_last_counter = counter
    return True


async def confirm_password(
    session,
    user: User,
    password: str,
    request: Request,
    *,
    message: str,
    code: int = status.HTTP_400_BAD_REQUEST,
) -> None:
    """Повторная проверка пароля перед опасным действием: смена пароля, второй
    фактор, аварийный архив. Со своим счетчиком и следом в журнале: иначе с
    украденной сессией пароль подбирали бы здесь, мимо лимитера входа."""
    key = f"reauth:{user.id}"
    if await ratelimit.is_locked(session, key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    # В счет до проверки, как при входе: иначе пачка одновременных запросов
    # проходила порог целиком.
    attempt = await ratelimit.attempt(session, key)
    if attempt is None:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    if await verify_password_async(password, user.password_hash):
        await ratelimit.forget(session, attempt)
        return
    await _reauth_logged(session, user, request)
    raise HTTPException(code, message)


async def reauth_failed(session, user: User, request: Request) -> None:
    await ratelimit.record_failure(session, f"reauth:{user.id}")
    await _reauth_logged(session, user, request)


async def _reauth_logged(session, user: User, request: Request) -> None:
    await audit.record(session, actor=user.username, action="reauth_failed", ip=peer_ip(request))
    await session.commit()


@router.post("/login", response_model=TokenOut)
async def login(body: LoginIn, request: Request, session: SessionDep) -> TokenOut:
    settings = get_settings()
    ip = peer_ip(request)
    key = ratelimit.subject(ip)

    if await ratelimit.is_locked(session, key):
        # 429, а не 401: иначе подбирающий не отличит блокировку от неверного
        # пароля и продолжит молотить, а мы продолжим считать ему попытки.
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY_LOGINS)
    # Попытка - в счет до проверки пароля (см. ratelimit.attempt).
    attempt = await ratelimit.attempt(session, key)
    if attempt is None:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY_LOGINS)

    user = await session.scalar(select(User).where(User.username == body.username))
    # Хеш проверяем ВСЕГДА, даже когда учетки нет: bcrypt заметно медленнее
    # остального запроса, и ответ "мгновенно 401" отличался бы от "401 через
    # 80 мс" - так перебором имен выясняют, кто в панели есть. Ответ и время
    # ответа должны быть одинаковыми во всех трех случаях: нет учетки,
    # отключена, неверный пароль.
    password_ok = await verify_password_async(
        body.password, user.password_hash if user else _DUMMY_HASH
    )
    # Белый список адресов учетки - уже здесь, а не только на следующих
    # запросах: иначе верный пароль с чужого адреса получал бы 200, и вход
    # работал бы подсказкой "пароль угадан".
    allowed_here = user is not None and machines.ip_allowed(user.allow_ips, ip)
    if user is None or user.disabled or not password_ok or not allowed_here:
        await _login_failed(session, attempt, body.username, ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")

    if user.totp_enabled:
        if not body.otp:
            # Отдельный код ответа, а не "неверный пароль": пароль-то верный, и
            # человеку надо показать поле для кода, а не заставлять гадать.
            await ratelimit.forget(session, attempt)
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "2fa_required"
            )
        otp_key = f"otp:{user.id}"
        otp = None
        if not await ratelimit.is_locked(session, otp_key, limit=OTP_LIMIT):
            otp = await ratelimit.attempt(session, otp_key, limit=OTP_LIMIT)
        if otp is None:
            # Верный код сейчас тоже не пускает: иначе блокировка ничего бы не
            # стоила тому, кто подбирает.
            await ratelimit.forget(session, attempt)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY_LOGINS)
        if not await consume_totp(session, user, body.otp):
            await _login_failed(session, attempt, user.username, ip, "неверный код 2FA")
            if otp.closes:
                await alerts.notify(
                    session,
                    f"🚨 Sekvyr: к учетной записи «{user.username}» подбирают код второго "
                    "фактора: пароль от нее уже известен, смените его",
                )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2fa_invalid")
        await ratelimit.forget(session, otp)

    await ratelimit.forget(session, attempt)

    # Удачный вход прежние неудачи с адреса не стирает: иначе подбирающий со
    # своей учеткой перемежал бы попытки удачными входами, и порог не наступал
    # бы никогда. Окно короткое, и свои опечатки из него уходят сами.
    await audit.record(session, actor=user.username, action="login", ip=ip)
    await session.commit()
    return TokenOut(
        access_token=create_access_token(
            user.username, settings.jwt_secret, settings.jwt_ttl_minutes, user.token_version
        )
    )


@router.get("/me", response_model=MeOut)
async def me(user: CurrentUser) -> MeOut:
    return MeOut(
        username=user.username,
        role=user.role,
        level=roles.level(user.role),
        role_title=roles.TITLES.get(user.role, user.role),
        totp_enabled=user.totp_enabled,
    )


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordIn, request: Request, user: CurrentUser, session: SessionDep
) -> None:
    """Смена своего пароля. Все прежние токены (в том числе на других
    устройствах) после нее недействительны - за это отвечает token_version."""
    await confirm_password(
        session, user, body.current_password, request, message="Текущий пароль неверен"
    )
    user.password_hash = await hash_password_async(body.new_password)
    await bump_token_version(session, user)
    await audit.record(
        session, actor=user.username, action="password_changed", ip=peer_ip(request)
    )
    await session.commit()


# --- второй фактор ---------------------------------------------------------


class TotpStartOut(BaseModel):
    secret: str
    otpauth_url: str


class TotpEnableIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)
    password: str = Field(min_length=1, max_length=256)


class TotpDisableIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=8)


def _fresh_token(user: User) -> TokenOut:
    settings = get_settings()
    return TokenOut(
        access_token=create_access_token(
            user.username, settings.jwt_secret, settings.jwt_ttl_minutes, user.token_version
        )
    )


@router.post("/2fa/start", response_model=TotpStartOut)
async def start_totp(
    request: Request, user: CurrentUser, session: SessionDep
) -> TotpStartOut:
    """Выдает новый секрет и ссылку для приложения. Фактор при этом еще НЕ
    включен: пока человек не подтвердил код, он может остаться без входа,
    например если приложение не сохранило секрет."""
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Второй фактор уже включён")
    secret = totp.new_secret()
    user.totp_secret = secret
    await session.commit()
    return TotpStartOut(
        secret=secret, otpauth_url=totp.provisioning_uri(secret, user.username)
    )


@router.post("/2fa/enable", response_model=TokenOut)
async def enable_totp(
    body: TotpEnableIn, request: Request, user: CurrentUser, session: SessionDep
) -> TokenOut:
    """Включение требует пароля, а не только кода: код показывает приложение,
    которое только что настроил тот, у кого сессия. С украденной сессией иначе
    можно было бы привязать вход к своему телефону и запереть хозяина.

    Прежние сессии закрываются, а эта получает новый токен. Иначе сессия,
    открытая до включения, проходила бы права "только со вторым фактором"."""
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Второй фактор уже включён")
    if not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Сначала запросите секрет")
    await confirm_password(session, user, body.password, request, message="Пароль неверен")
    if not await consume_totp(session, user, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Код не подошёл")
    user.totp_enabled = True
    await bump_token_version(session, user)
    await audit.record(
        session, actor=user.username, action="totp_enabled", ip=peer_ip(request)
    )
    await session.commit()
    return _fresh_token(user)


@router.post("/2fa/disable", response_model=TokenOut)
async def disable_totp(
    body: TotpDisableIn, request: Request, user: CurrentUser, session: SessionDep
) -> TokenOut:
    """Выключение требует и пароля, и кода: иначе достаточно на минуту оставить
    открытой вкладку или узнать пароль, чтобы второй фактор исчез. Прежние
    сессии закрываются, эта получает новый токен."""
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Второй фактор не включен")
    await confirm_password(session, user, body.password, request, message="Пароль неверен")
    if not await consume_totp(session, user, body.code):
        await reauth_failed(session, user, request)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Код не подошёл")
    user.totp_enabled = False
    user.totp_secret = ""
    user.totp_last_counter = 0
    await bump_token_version(session, user)
    await audit.record(
        session, actor=user.username, action="totp_disabled", ip=peer_ip(request)
    )
    await session.commit()
    return _fresh_token(user)
