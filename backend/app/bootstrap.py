import hashlib
import hmac
import logging

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import alerts, audit, roles, settings_store
from app.config import Settings
from app.models import User
from app.security import MIN_PASSWORD_LEN, hash_password

log = logging.getLogger("sekvyr.bootstrap")

# Отпечаток пароля, которым уже делали аварийный сброс. HMAC на секрете JWT, а не
# голый хеш: пароль владельца в базе и так лежит bcrypt-хешем, и быстрый хеш
# рядом с ним сделал бы подбор дешевле.
RESET_MARK = "bootstrap_reset_mark"


def _mark(settings: Settings) -> str:
    raw = f"{settings.admin_user}\0{settings.admin_password}".encode()
    return hmac.new(settings.jwt_secret.encode(), raw, hashlib.sha256).hexdigest()


def _check_length(settings: Settings) -> None:
    # Этот пароль станет настоящим, а проверить его длину больше негде: через
    # API владелец не заводится и аварийный сброс не идет.
    if len(settings.admin_password) < MIN_PASSWORD_LEN:
        raise RuntimeError(
            f"SEKVYR_ADMIN_PASSWORD короче {MIN_PASSWORD_LEN} символов — "
            "задайте длиннее. Панель не запущена в целях безопасности."
        )


async def ensure_owner(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Заводит владельца панели ТОЛЬКО при первом старте, когда учеток еще нет.

    Пароль из .env - начальный: дальше он меняется в панели и обратно из .env не
    пересинхронизируется, иначе смена пароля откатывалась бы при каждом рестарте.

    Аварийный вход: SEKVYR_ADMIN_PASSWORD_RESET=1 сбрасывает пароль владельца и
    отключает второй фактор. Нужен, когда потеряны и пароль, и второй фактор;
    после входа флаг убирают. Забытый флаг не сбрасывает пароль на каждом
    рестарте: одним и тем же паролем из .env сброс делается один раз, иначе
    он молча откатывал бы новый пароль и снова снимал второй фактор.
    """
    async with session_factory() as session:
        user = await session.scalar(
            select(User).where(User.username == settings.admin_user)
        )
        if user is None:
            if await session.scalar(select(func.count()).select_from(User)):
                # Учетки есть, а такой нет: в .env сменили имя владельца. Заводить
                # по нему нового владельца значило бы впускать в панель любого,
                # кто может править .env, мимо журнала и оповещений.
                log.warning(
                    "в .env владелец %s, а в панели такой учетки нет: новая не "
                    "заводится. Для аварийного входа верните прежнее имя и "
                    "задайте SEKVYR_ADMIN_PASSWORD_RESET=1",
                    settings.admin_user,
                )
                return
            _check_length(settings)
            session.add(
                User(
                    username=settings.admin_user,
                    password_hash=hash_password(settings.admin_password),
                    role=roles.OWNER,
                )
            )
            await audit.record(
                session, actor="система", action="owner_created", target=settings.admin_user
            )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()  # другой воркер успел первым
            else:
                log.info("создан владелец панели: %s", settings.admin_user)
        elif settings.admin_password_reset:
            mark = _mark(settings)
            if hmac.compare_digest(await settings_store.get(session, RESET_MARK), mark):
                log.warning(
                    "SEKVYR_ADMIN_PASSWORD_RESET все еще стоит, а сброс этим паролем "
                    "уже был: повтор не делается. Уберите флаг из .env. Для нового "
                    "сброса задайте в .env другой SEKVYR_ADMIN_PASSWORD"
                )
                return
            _check_length(settings)
            user.password_hash = hash_password(settings.admin_password)
            user.totp_enabled = False
            user.totp_secret = ""
            user.disabled = False
            # Белый список адресов тоже снимается: владелец, который потерял
            # доступ из-за смены адреса, иначе остался бы запертым и после
            # аварийного сброса.
            user.allow_ips = ""
            user.token_version += 1  # все прежние сессии становятся недействительны
            await audit.record(
                session,
                actor="система",
                action="owner_password_reset",
                target=user.username,
                detail="аварийный сброс по SEKVYR_ADMIN_PASSWORD_RESET",
            )
            await settings_store.put(session, RESET_MARK, mark)
            await session.commit()
            log.warning(
                "АВАРИЙНЫЙ СБРОС пароля владельца выполнен — удалите "
                "SEKVYR_ADMIN_PASSWORD_RESET из .env и перезапустите панель"
            )
            await alerts.notify_later(
                session_factory,
                f"🚨 Sekvyr: аварийный сброс пароля владельца «{user.username}» по "
                "SEKVYR_ADMIN_PASSWORD_RESET, второй фактор выключен. Если это "
                "были не вы, панель в чужих руках",
            )
