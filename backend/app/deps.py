"""Зависимости FastAPI: сессия базы, текущий пользователь, роль.

Единая точка проверки. Каждый маршрут, кроме входа и /health, зависит от
`CurrentUser`, поэтому проверки ниже обойти нельзя - их не нужно повторять в
каждом роутере, и невозможно забыть в новом. Что здесь проверяется:

  * подпись и срок токена;
  * что учетка еще существует и не отключена;
  * что токен не пережил смену пароля (версия);
  * что наблюдатель ничего не меняет.

Права на конкретные проекты и пути проверяет app/access.py.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import machines, roles
from app.clientip import client_ip
from app.config import get_settings
from app.db import get_session
from app.models import User
from app.sealbox import SealBox
from app.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)

SessionDep = Annotated[AsyncSession, Depends(get_session)]

# изменяющие методы: наблюдателю запрещены
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# ...кроме своей учетки: сменить себе пароль и второй фактор может кто угодно
_SELF_SERVICE_PREFIX = "/api/auth/"


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: SessionDep,
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Недействительный или отсутствующий токен"
    )
    if credentials is None:
        raise unauthorized
    payload = decode_access_token(credentials.credentials, get_settings().jwt_secret)
    if payload is None:
        raise unauthorized
    user = await session.scalar(select(User).where(User.username == payload["sub"]))
    if user is None or user.disabled:
        raise unauthorized
    # токен, выпущенный до смены пароля (иная версия), больше не действителен
    if payload.get("ver", 0) != user.token_version:
        raise unauthorized
    # Адрес проверяем на каждом запросе, а не только при входе: иначе токен,
    # уехавший вместе с сессией, работал бы откуда угодно до конца своего срока.
    if not machines.ip_allowed(user.allow_ips, peer_ip(request)):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Этой учётной записи не разрешён вход с вашего адреса",
        )
    if (
        user.role == roles.VIEWER
        and request.method in _WRITE_METHODS
        and not request.url.path.startswith(_SELF_SERVICE_PREFIX)
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Учётная запись только для просмотра — изменения запрещены",
        )
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def get_owner(user: CurrentUser) -> User:
    """Действия над панелью целиком: учетки, ключи, настройки."""
    if user.role != roles.OWNER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Требуются права владельца панели")
    return user


OwnerUser = Annotated[User, Depends(get_owner)]


def min_level(level: int):
    """Зависимость "роль не ниже такой-то". Уровнями, а не перечислением ролей:
    новая роль в середине шкалы не потребует править каждый роутер."""

    async def check(user: CurrentUser) -> User:
        if roles.level(user.role) < level:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Недостаточно прав для этого раздела"
            )
        return user

    return check


# Журнал и список учеток - с уровня ответственного: разработчику незачем видеть,
# кто и когда заходил в панель.
MaintainerUser = Annotated[User, Depends(min_level(roles.LEVELS[roles.MAINTAINER]))]


def peer_ip(request: Request) -> str:
    """Адрес клиента с учетом числа доверенных прокси-хопов."""
    return client_ip(request, get_settings().trusted_proxy_hops)


def get_sealbox(request: Request) -> SealBox:
    """Состояние корневого ключа этого процесса."""
    return request.app.state.sealbox


BoxDep = Annotated[SealBox, Depends(get_sealbox)]


async def get_unsealed_box(box: BoxDep) -> SealBox:
    """То же, но с отказом, если панель заперта.

    Ответ 503, а не 403: это не "вам нельзя", а "панель сейчас не может" -
    и лечится подачей долей, а не правами. Каждый маршрут, который трогает
    значения, зависит от ЭТОЙ зависимости, поэтому забыть проверку нельзя.
    """
    if not box.unsealed:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Панель заперта: чтобы читать значения, введите корневой ключ",
        )
    return box


UnsealedBox = Annotated[SealBox, Depends(get_unsealed_box)]
