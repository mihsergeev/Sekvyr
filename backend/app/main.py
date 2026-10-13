import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError, IntegrityError

from app import (
    alerts,
    audit_ship,
    audit_watch,
    backups,
    crypto,
    envkeys,
    fleet_watch,
    heartbeat,
    lint_watch,
    sealbox,
    secrets_store,
    security,
)
from app.api import audit as audit_api
from app.api import branding
from app.api import auth, e2e as e2e_api, health, machine
from app.api import machines_admin
from app.api import migrate, ops, policies, projects, search, secrets
from app.api import users as users_api
from app.api import vault as vault_api
from app.bootstrap import ensure_owner
from app.config import Settings, get_settings
from app.db import create_engine_and_factory

log = logging.getLogger("sekvyr.main")

_WEAK_SECRETS = {"", "changeme", "dev-insecure-change-me"}
_WEAK_PASSWORDS = {"", "changeme", "admin", "password"}


def _enforce_secrets(settings: Settings) -> None:
    """Отказываемся стартовать с дефолтными секретами.

    Панель хранит чужие пароли и ключи. Слабый JWT-секрет здесь означает не
    "неудобно", а "любой желающий подписывает себе токен владельца", поэтому
    выбор такой: либо секреты заданы, либо панель не поднимается. В debug
    проверка снимается - иначе с ней невозможно работать локально.
    """
    if settings.debug:
        return
    if settings.jwt_secret in _WEAK_SECRETS or len(settings.jwt_secret) < 32:
        raise RuntimeError(
            "SEKVYR_JWT_SECRET не задан или слишком слабый — задайте случайный "
            "секрет (openssl rand -hex 32). Панель не запущена в целях безопасности."
        )
    if settings.admin_password in _WEAK_PASSWORDS:
        raise RuntimeError(
            "SEKVYR_ADMIN_PASSWORD не задан или дефолтный — задайте надёжный "
            "пароль. Панель не запущена в целях безопасности."
        )


async def _auto_unseal(app: FastAPI, settings: Settings) -> None:
    """Отпирание корневым ключом из переменной или файла.

    Молчаливого "не получилось" здесь быть не должно: панель, поднявшаяся
    запертой там, где её ждали отпертой, перестает отдавать секреты
    машинам - и это надо видеть в логе первой же строкой, а не выяснять по
    отказам на нодах.
    """
    key = sealbox.root_from_env(settings.root_key, settings.root_key_file)
    if key is None:
        await _warn_if_sealed(app, settings)
        return
    async with app.state.session_factory() as session:
        meta = await sealbox.read_meta(session)
    if not meta.initialized:
        log.warning("корневой ключ задан, но сейф ещё не заведён — панель заперта")
        return
    if not sealbox.check_root(key, meta):
        log.error(
            "заданный корневой ключ не подходит к этой базе — панель осталась запертой"
        )
        return
    app.state.sealbox.set_root(key)
    log.info("панель открыта корневым ключом из окружения")


async def _warn_if_sealed(app: FastAPI, settings: Settings) -> None:
    """Панель поднялась запертой там, где её ждали отпертой.

    Именно этот случай оповещение и должно ловить: перезагрузился хост, панель
    вернулась без ключа, машины перестали получать значения, и никто об этом не
    знает, потому что люди в панель заходят раз в неделю. Настройки каналов
    лежат открытым текстом ровно ради такого старта (см. app/alerts.py).
    """
    async with app.state.session_factory() as session:
        meta = await sealbox.read_meta(session)
        if not meta.initialized or not meta.auto_unseal:
            return
        await alerts.notify(
            session,
            "🔒 Sekvyr: панель поднялась ЗАПЕРТОЙ, хотя должна была открыться сама — "
            "значения машинам сейчас не выдаются",
        )


NO_SUCH_NUMBER = "Такого объекта нет: номер вне допустимого диапазона"
TOO_LONG_FOR_DB = "Значение длиннее, чем помещается в базу"
NUL_IN_REQUEST = "В запросе нулевой символ: такие строки база не хранит"
ALREADY_THERE = "Такая запись уже есть: ее только что завели параллельно. Обновите страницу"
TRY_AGAIN = "Запрос столкнулся с параллельным и отменен: повторите его"
ENV_GONE = "Окружение удалили, пока выполнялся запрос: обновите страницу"
RELATED_GONE = "Связанную запись удалили, пока выполнялся запрос: обновите страницу"
LOST_KEY = (
    "Значение зашифровано ключом окружения, которого больше нет: его не открыть. "
    "Запишите этот ключ заново"
)
LOST_ACTIVE_KEY = (
    "У окружения нет действующего ключа шифрования: база повреждена или смена "
    "ключа оборвалась. Восстановите базу из бэкапа"
)


def create_app() -> FastAPI:
    # httpx на INFO печатает URL каждого запроса - а в URL уезжают токены
    # (Telegram Bot API кладет токен прямо в путь). Оставляем warning и выше,
    # чтобы валидный секрет не оседал в выводе `docker logs`.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    settings = get_settings()
    engine, session_factory = create_engine_and_factory(settings.db_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        _enforce_secrets(settings)
        await ensure_owner(session_factory, settings)
        await _auto_unseal(app, settings)
        # Фоновые задачи обслуживания: копия журнала наружу и присмотр за
        # отметкой о бэкапе. Обе молчаливы, пока не настроены, и обе не должны
        # мешать панели работать - поэтому живут отдельными задачами.
        background = [
            asyncio.create_task(audit_ship.run(session_factory, settings)),
            asyncio.create_task(backups.watch(session_factory, settings)),
            asyncio.create_task(heartbeat.run(session_factory, settings, app.state.sealbox)),
            # Обход значений: замечание, которое видно только тому, кто зашел в
            # окружение, - половина пользы.
            asyncio.create_task(lint_watch.watch(session_factory, app.state.sealbox)),
            # Присмотр за парком: сервер, замолчавший на сутки, и недельная
            # сводка правок. Значений не читает, поэтому работает всегда.
            asyncio.create_task(fleet_watch.watch(session_factory)),
            # Цепочка журнала раз в сутки: правку в обход панели должно быть
            # видно, даже если кнопку проверки никто не нажмет.
            asyncio.create_task(audit_watch.watch(session_factory)),
        ]
        try:
            yield
        finally:
            for task in background:
                task.cancel()
            await asyncio.gather(*background, return_exceptions=True)
            # ключ живет только в памяти процесса - уходя, забираем его с собой
            app.state.sealbox.seal()
            await engine.dispose()

    # Схему API отдаем только в debug: снаружи доступен машинный контур, и
    # публиковать рядом с ним полный список маршрутов панели незачем.
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        docs_url="/api/docs" if settings.debug else None,
        openapi_url="/api/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )
    app.state.engine = engine
    app.state.session_factory = session_factory
    # Корневой ключ живет здесь, а не в глобальной переменной модуля: так
    # "запереть" означает ровно этот процесс, а тесты не наследуют чужое
    # состояние сейфа.
    app.state.sealbox = sealbox.SealBox()

    # Плохое имя ключа - ошибка человека, а не панели: 400 с объяснением, а не
    # 500. Одно место на все маршруты, которые пишут ключи.
    @app.exception_handler(secrets_store.BadName)
    async def _bad_name(_request: Request, exc: secrets_store.BadName) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    # Значение не расшифровалось или не сошлось с ключом при живом корневом
    # ключе: правка базы мимо панели или оборванная ротация. Человек должен это
    # увидеть словами, в каком бы маршруте ни случилось чтение.
    @app.exception_handler(crypto.DecryptionError)
    async def _tampered(_request: Request, _exc: crypto.DecryptionError) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"detail": "Значение не сошлось с ключом — возможна правка базы в обход панели"},
        )

    # Ключ без действующего значения (удален, отдан родителю, единственная
    # версия ждет подтверждения): 404 с объяснением, а не 500 в любом маршруте,
    # который его читает.
    @app.exception_handler(secrets_store.SecretNotFound)
    async def _no_value(_request: Request, exc: secrets_store.SecretNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    # Номер больше, чем помещается в столбец: у Postgres это все, что больше
    # 2 147 483 647, у SQLite - больше 2^63. База отвечает исключением, и любая
    # ручка с номером в пути или в теле отдавала 500 (нашел фаззинг схемы).
    # Объекта с таким номером быть не может, поэтому 404. Остальные ошибки
    # базы идут дальше как были: в лог с трассировкой и 500.
    @app.exception_handler(OverflowError)
    async def _number_too_big(_request: Request, _exc: OverflowError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": NO_SUCH_NUMBER})

    @app.exception_handler(DBAPIError)
    async def _database_refused(_request: Request, exc: DBAPIError) -> JSONResponse:
        text = str(exc.orig if exc.orig is not None else exc)
        if "out of int" in text and "range" in text:
            return JSONResponse(status_code=404, content={"detail": NO_SUCH_NUMBER})
        if "value too long" in text:
            return JSONResponse(status_code=400, content={"detail": TOO_LONG_FOR_DB})
        # Нулевой символ в строке Postgres не хранит вовсе, а SQLite в тестах
        # принимает: имя ключа с \x00 в поиске, фильтре журнала или названии
        # группы отдавало 500 только на настоящей базе (нашел фаззинг на
        # Postgres). В значение переменной окружения такой символ все равно не
        # попадет: строки окружения им заканчиваются.
        if "0x00" in text or "invalid byte sequence" in text:
            return JSONResponse(status_code=400, content={"detail": NUL_IN_REQUEST})
        # Проверку "уже есть" два запроса прошли одновременно, и второй
        # уперся в уникальный индекс: это повтор, а не сбой панели.
        lowered = text.lower()
        if isinstance(exc, IntegrityError) and ("unique" in lowered or "duplicate key" in lowered):
            # След в логе: так же отвечает и ошибка в самом коде, а не только гонка.
            log.warning("нарушение уникальности, ответ 409: %s", text[:300])
            return JSONResponse(status_code=409, content={"detail": ALREADY_THERE})
        # Встречные блокировки: Postgres отменил одну из транзакций целиком.
        if "deadlock detected" in lowered:
            return JSONResponse(status_code=409, content={"detail": TRY_AGAIN})
        # Внешний ключ: родителя (проект, окружение, ключ) удалили параллельно.
        # Данные целы, и это не сбой панели. Страховка за местами, где
        # удаление не ловится раньше (lock_env, создание окружения).
        if isinstance(exc, IntegrityError) and "foreign key" in lowered:
            log.warning("внешний ключ, ответ 409: %s", text[:300])
            return JSONResponse(status_code=409, content={"detail": RELATED_GONE})
        raise exc

    @app.exception_handler(secrets_store.EnvironmentGone)
    async def _env_gone(_request: Request, _exc: secrets_store.EnvironmentGone) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": ENV_GONE})

    # Ключ переехал, пока запрос ждал блокировку: права проверялись по
    # прежнему месту, и писать по новому нельзя.
    @app.exception_handler(secrets_store.SecretChanged)
    async def _moved(_request: Request, exc: secrets_store.SecretChanged) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    # Версия зашифрована поколением ключа окружения, которого нет (наследие
    # гонки записи со сменой ключа в версиях до 1.0.0). Значение не открыть;
    # человеку нужно знать, что делать, а не видеть голую 500.
    @app.exception_handler(envkeys.MissingKeyError)
    async def _lost_key(_request: Request, exc: envkeys.MissingKeyError) -> JSONResponse:
        log.error("нет ключа окружения: %s", exc)
        # Нет действующего ключа - не записать ничего, и совет "запишите
        # заново" тут неверен.
        detail = LOST_ACTIVE_KEY if "активного" in str(exc) else LOST_KEY
        return JSONResponse(status_code=500, content={"detail": detail})

    # Открытый текст в e2e-проект: маршруты, которые пишут значения, ловят это
    # сами, а этот ответ - для любой дороги, которую забыли.
    @app.exception_handler(secrets_store.SealedValueRequired)
    async def _sealed_only(_request: Request, exc: secrets_store.SealedValueRequired) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(security.PasswordTooLong)
    async def _long_password(_request: Request, exc: security.PasswordTooLong) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    # Ошибка проверки без самого ввода: FastAPI по умолчанию возвращает
    # присланное целиком, и два мегабайта мусора на вход без учетки
    # оборачивались двумя мегабайтами ответа. Интерфейсу хватает loc и msg.
    @app.exception_handler(RequestValidationError)
    async def _invalid(_request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"type": e.get("type", ""), "loc": list(e.get("loc", ())), "msg": e.get("msg", "")}
            for e in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(users_api.router, prefix="/api")
    app.include_router(audit_api.router, prefix="/api")
    app.include_router(vault_api.router, prefix="/api")
    app.include_router(policies.router, prefix="/api")
    app.include_router(projects.router, prefix="/api")
    app.include_router(secrets.router, prefix="/api")
    app.include_router(search.router, prefix="/api")
    app.include_router(machines_admin.router, prefix="/api")
    app.include_router(ops.router, prefix="/api")
    app.include_router(migrate.router, prefix="/api")
    app.include_router(e2e_api.router, prefix="/api")
    app.include_router(branding.router, prefix="/api")
    # Машинный контур стоит на отдельном пути: он единственный открыт наружу, и
    # обратный прокси отличает его от админки именно по префиксу (compose.caddy).
    app.include_router(machine.router, prefix="/api")
    return app


app = create_app()
