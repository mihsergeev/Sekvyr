import asyncio

from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from app.config import get_settings

router = APIRouter(tags=["system"])

# Столько ждем базу: health должен успеть ответить раньше, чем истечет таймаут
# healthcheck контейнера и ожидание в quickstart.
DB_TIMEOUT = 3.0


@router.get("/health")
async def health(request: Request, response: Response) -> dict[str, str | bool]:
    """Готовность панели: отвечает процесс, доступна база, подан корневой ключ.

    Безусловное "ok" было бы враньем в обе стороны. При недоступной базе панель
    не впустит человека, а при запертом сейфе не отдаст ни одного значения
    машине - и то, и другое должно быть видно снаружи, иначе мониторинг
    показывает зеленое, пока на нодах не поднимаются сервисы.

    Состояние замка - это `degraded`, а не `down`: панель жива, в нее можно войти
    и подать доли. Ответ при этом 200, потому что 503 в этом состоянии заставил
    бы оркестратор перезапускать контейнер по кругу, а перезапуск ровно ничего
    не чинит - ключ подается руками.
    """
    settings = get_settings()
    sealed = not request.app.state.sealbox.unsealed
    body: dict[str, str | bool] = {
        "status": "ok",
        "version": settings.version,
        "db": "ok",
        "sealed": sealed,
        # Зона, в которой панель показывает время. Не догадка браузера: панель
        # и её журнал должны читаться одинаково у всех, кто в нее смотрит.
        "timezone": settings.timezone,
    }
    try:
        async with asyncio.timeout(DB_TIMEOUT):
            async with request.app.state.session_factory() as session:
                await session.execute(text("SELECT 1"))
    except Exception:
        body["status"] = "degraded"
        body["db"] = "down"
        response.status_code = 503
        return body
    if sealed:
        body["status"] = "sealed"
    return body
