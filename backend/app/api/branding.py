"""Логотип и название компании в заголовке вкладки.

Панель ставят в компании, и в шапке у нее логотип компании, а не Sekvyr: так её
узнают среди других вкладок, и так она выглядит своей, а не чужой утилитой.

Хранится один файл логотипа и, если у логотипа есть своя версия для темного
фона, второй. Под тему их подстраивает браузер при показе (см. logoAdapt.ts):
тогда перекраска не отстает от файла, когда его заменят, и улучшение перекраски
доходит до уже залитых логотипов без перезаливки.

Лежит все в базе, в настройках панели, а не файлом рядом с ней. Бэкап Sekvyr -
это дамп базы: файл в каталоге данных при восстановлении на новой машине
потерялся бы, а мета в базе продолжала бы говорить "логотип есть".

Оформление доступно на экране входа. Изменять его может владелец панели.
"""

import base64
import binascii
import hashlib
import json
import re

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit, settings_store
from app.deps import OwnerUser, SessionDep, peer_ip

router = APIRouter(prefix="/branding", tags=["branding"])

META = "branding_meta"
LOGO = "branding_logo"
LOGO_DARK = "branding_logo_dark"
COMPANY_NAME = "branding_company_name"
LOGO_FIELDS = (("media", "logo_revision", LOGO), ("dark_media", "dark_logo_revision", LOGO_DARK))

MAX_BYTES = 512 * 1024
# base64 раздувает файл на треть, data-URL добавляет свою приставку.
MAX_FIELD = 720_000

# Тип определяем по содержимому, а не по имени и не по заголовку: и то, и другое
# задает загружающий.
_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)

# Исполняемого в SVG быть не должно. Через <img> браузер скрипты внутри SVG и так
# не выполняет, но файл отдается с адреса панели, где лежат чужие секреты, и его
# можно открыть напрямую. Режем на входе, а при отдаче еще и запираем в песочницу.
#
# Ссылки - только внутрь самого файла (#id) или на встроенную картинку
# data:image/png и подобные: так устроены обычные логотипы, а все прочее, в том
# числе спрятанное за &#...; или префиксом пространства имен, - отказ. Каждая
# ветка начинается с короткого литерала и не перебирает остаток файла: прежний
# вариант с [^>]* на полмегабайта без > считал около двух минут.
_SAFE_REF = rb"(?!#|data:image/(?:png|jpeg|gif|webp)[;,])"
# Кавычки и пробелы перед адресом - без отката (?+, *+): иначе проверка
# "адрес не начинается с #" срабатывала бы на саму кавычку.
_SVG_BAD = re.compile(
    rb"<\s*(?:[\w.-]+:)?(?:script|foreignObject|iframe)\b|javascript:|\son\w+\s*=|<!ENTITY"
    rb"|\bhref\s*+=\s*+[\"']?+\s*+" + _SAFE_REF + rb"|url\(\s*+[\"']?+\s*+" + _SAFE_REF
    + rb"|@import|attributeName\s*=\s*[\"']?\s*(?:[\w.-]+:)?href",
    re.I,
)


class BrandingOut(BaseModel):
    logo: bool = False
    # Подпись на экране входа.
    title: str = ""
    company_name: str = ""
    # Оформление: auto - подстроить цвета под тему, always - на плашке, never - как есть.
    plate: str = "auto"
    dark_logo: bool = False
    # Счетчик для старых клиентов; кэш современных клиентов привязан к файлу.
    version: int = 0
    logo_revision: str = ""
    dark_logo_revision: str = ""


class BrandingIn(BaseModel):
    # base64 или data-URL. Пусто - файл не меняем, сохраняем только настройки.
    data: str = Field(default="", max_length=MAX_FIELD)
    # Вариант для темной темы: пусто - не менять, dark_remove - убрать.
    dark: str = Field(default="", max_length=MAX_FIELD)
    dark_remove: bool = False
    plate: str = Field(default="auto", pattern="^(auto|always|never)$")
    title: str = Field(default="", max_length=64)


class CompanyNameIn(BaseModel):
    company_name: str = Field(
        max_length=64,
        pattern=r"^[^\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]*$",
    )


def _decode(raw: str) -> bytes:
    raw = raw.strip()
    if raw.startswith("data:"):
        raw = raw.split(",", 1)[-1]
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Файл повреждён") from None
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Пустой файл")
    if len(data) > MAX_BYTES:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"Файл больше {MAX_BYTES // 1024} КБ — уменьшите логотип",
        )
    return data


def _sniff(data: bytes) -> str:
    """Тип картинки по содержимому. Все, что не картинка, - отказ."""
    for magic, media in _MAGIC:
        if data.startswith(magic):
            return media
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    head = data[:1024].lstrip().lower()
    if head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in head:
        if _SVG_BAD.search(data):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "В SVG есть скрипты или внешние ссылки — сохраните логотип без них или загрузите PNG",
            )
        return "image/svg+xml"
    raise HTTPException(status.HTTP_400_BAD_REQUEST, "Нужен файл PNG, JPEG, WebP, GIF или SVG")


def _checked(raw: str) -> tuple[bytes, str] | None:
    """Файл из запроса вместе с типом - или None, если его не прислали."""
    if not raw.strip():
        return None
    data = _decode(raw)
    return data, _sniff(data)


def _parse_meta(raw: str) -> dict:
    """Нет меты или она битая - логотипа нет."""
    try:
        meta = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return meta if isinstance(meta, dict) else {}


def _out(meta: dict, company_name: str) -> BrandingOut:
    return BrandingOut(
        logo=bool(meta.get("media")),
        title=meta.get("title", ""),
        company_name=company_name,
        plate=meta.get("plate", "auto"),
        dark_logo=bool(meta.get("dark_media")),
        version=int(meta.get("v", 0)),
        logo_revision=meta.get("logo_revision", ""),
        dark_logo_revision=meta.get("dark_logo_revision", ""),
    )


def _logo_revision(data: bytes) -> str:
    return "h-" + hashlib.sha256(data).hexdigest()


def _stored_logo(value: str) -> bytes | None:
    try:
        return base64.b64decode(value, validate=True) or None
    except (binascii.Error, ValueError):
        return None


def _fill_legacy_revisions(meta: dict, values: dict[str, str]) -> None:
    for media, revision, key in LOGO_FIELDS:
        if meta.get(media) and not meta.get(revision):
            data = _stored_logo(values.get(key, ""))
            if data is not None:
                meta[revision] = _logo_revision(data)


async def _current(session: AsyncSession) -> BrandingOut:
    values = await settings_store.get_keys(session, META, COMPANY_NAME)
    meta = _parse_meta(values.get(META, ""))
    if any(meta.get(media) and not meta.get(revision) for media, revision, _ in LOGO_FIELDS):
        # Старый дамп не хранит хеши обеих картинок. Читаем мету и файлы одним
        # запросом: конкурентная загрузка не должна смешать разные версии.
        values = await settings_store.get_keys(session, META, COMPANY_NAME, LOGO, LOGO_DARK)
        meta = _parse_meta(values.get(META, ""))
        _fill_legacy_revisions(meta, values)
    return _out(meta, values.get(COMPANY_NAME, ""))


@router.get("", response_model=BrandingOut)
async def get_branding(session: SessionDep, response: Response) -> BrandingOut:
    """Без входа: экран входа рисуется до авторизации."""
    response.headers["Cache-Control"] = "no-store"
    return await _current(session)


@router.put("/company-name", response_model=BrandingOut)
async def set_company_name(
    body: CompanyNameIn, request: Request, user: OwnerUser, session: SessionDep
) -> BrandingOut:
    await settings_store.upsert(session, COMPANY_NAME, body.company_name.strip())
    await audit.record(session, actor=user.username, action="branding_company_set", ip=peer_ip(request))
    await session.commit()
    return await _current(session)


async def _serve(session: AsyncSession, dark: bool, version: str) -> Response:
    key = LOGO_DARK if dark else LOGO
    values = await settings_store.get_keys(session, META, key)
    meta = _parse_meta(values.get(META, ""))
    media = meta.get("dark_media" if dark else "media")
    data = _stored_logo(values.get(key, ""))
    if not media or data is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Логотип не задан", headers={"Cache-Control": "no-store"})
    addressed = version.startswith("h-")
    if addressed and version != _logo_revision(data):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Логотип изменился", headers={"Cache-Control": "no-store"})
    return Response(
        content=data,
        media_type=media,
        headers={
            # Файл чужой: ничего не подгружать, не угадывать тип, а открытый
            # напрямую - жить в песочнице без доступа к панели.
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "X-Content-Type-Options": "nosniff",
            # Числовой адрес может повториться после восстановления из бэкапа.
            "Cache-Control": "public, max-age=604800" if addressed else "no-store",
        },
    )


@router.get("/logo")
async def get_logo(session: SessionDep, v: str = "") -> Response:
    return await _serve(session, dark=False, version=v)


@router.get("/logo-dark")
async def get_logo_dark(session: SessionDep, v: str = "") -> Response:
    """Своя версия логотипа для темного фона, если у компании такая есть."""
    return await _serve(session, dark=True, version=v)


@router.post("/save", response_model=BrandingOut)
async def save_branding(
    body: BrandingIn,
    request: Request,
    user: OwnerUser,
    session: SessionDep,
) -> BrandingOut:
    """Логотип и его настройки. Файл необязателен, если логотип уже есть:
    оформление и подпись меняют, не выбирая тот же файл заново."""
    # Оба файла проверяем до записи: иначе годный основной лег бы в базу, а
    # отвергнутый темный оставил бы мету от прежнего.
    main = _checked(body.data)
    dark = _checked(body.dark)
    await settings_store.lock(session, META, "{}")
    old = _parse_meta(await settings_store.get(session, META))
    if main is None and not old.get("media"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Выберите файл логотипа")

    meta = dict(old)
    changed: list[str] = []
    if main is not None:
        data, media = main
        await settings_store.put(session, LOGO, base64.b64encode(data).decode())
        meta["media"] = media
        meta["logo_revision"] = _logo_revision(data)
        changed.append(f"{media}, {len(data)} байт")
    if dark is not None:
        data, media = dark
        await settings_store.put(session, LOGO_DARK, base64.b64encode(data).decode())
        meta["dark_media"] = media
        meta["dark_logo_revision"] = _logo_revision(data)
        changed.append(f"тёмная тема: {media}, {len(data)} байт")
    elif body.dark_remove and old.get("dark_media"):
        await settings_store.put(session, LOGO_DARK, "")
        meta.pop("dark_media", None)
        meta.pop("dark_logo_revision", None)
        changed.append("вариант для тёмной темы убран")

    meta["plate"] = body.plate
    meta["title"] = body.title.strip()[:64]
    meta["v"] = int(old.get("v", 0)) + 1
    missing = [key for media, revision, key in LOGO_FIELDS if meta.get(media) and not meta.get(revision)]
    if missing:
        _fill_legacy_revisions(meta, await settings_store.get_keys(session, *missing))
    await settings_store.put(session, META, json.dumps(meta, ensure_ascii=False))

    await audit.record(
        session,
        actor=user.username,
        action="branding_set",
        detail="; ".join(changed) or "настройки",
        ip=peer_ip(request),
    )
    await session.commit()
    return _out(meta, await settings_store.get(session, COMPANY_NAME))


@router.post("/reset", response_model=BrandingOut)
async def reset_branding(request: Request, user: OwnerUser, session: SessionDep) -> BrandingOut:
    """Вернуть стандартный логотип. Версия растет и здесь: иначе браузер показывал
    бы старую картинку из кэша по прежнему адресу."""
    await settings_store.lock(session, META, "{}")
    old = _parse_meta(await settings_store.get(session, META))
    meta = {"v": int(old.get("v", 0)) + 1}
    await settings_store.put(session, LOGO, "")
    await settings_store.put(session, LOGO_DARK, "")
    await settings_store.put(session, META, json.dumps(meta))
    await audit.record(
        session,
        actor=user.username,
        action="branding_reset",
        ip=peer_ip(request),
    )
    await session.commit()
    return _out(meta, await settings_store.get(session, COMPANY_NAME))
