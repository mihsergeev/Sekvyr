"""Обслуживание: оповещения, состояние бэкапа, аварийный архив.

Раздел для владельца панели, а не для того, кто ей пользуется. Здесь три вещи,
которые нужны в день происшествия и которые поздно настраивать в этот же день:

  * каналы оповещений и копия журнала наружу;
  * взгляд на бэкап - снимают ли его вообще и когда сняли в последний раз;
  * аварийный архив: все значения одним запечатанным файлом.

Про архив стоит сказать прямо: это единственное место, где секреты выходят из
панели все сразу. Поэтому он требует пароля владельца и второго фактора,
пишется в журнал и уходит в оповещения. Спрятать сборку архива нельзя.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app import alerts, audit, backups, emergency, settings_store, urlguard
from app.config import get_settings
from app.deps import OwnerUser, SessionDep, UnsealedBox, peer_ip
from app.api.auth import confirm_password, consume_totp, reauth_failed

router = APIRouter(prefix="/ops", tags=["ops"])

# Пароль архива придется вводить руками через год после того, как его придумали,
# поэтому короткий здесь не годится: подобрать его будут офлайн, без лимитов
# панели, имея файл на руках.
MIN_ARCHIVE_PASSWORD = 12

KEEP = ""  # пустое поле в запросе = "не менять"
CLEAR = "-"  # так канал выключают


class AlertsOut(BaseModel):
    """Токен и адреса наружу не отдаем целиком: панель показывает только хвост.

    Смысл не в недоверии владельцу, а в том, что интерфейс открыт в браузере,
    попадает на снимки экрана и в записи демонстраций. Полное значение владелец
    и так знает - он его вводил.
    """

    telegram_token: str = ""
    telegram_chat: str = ""
    telegram_api: str = ""
    webhook: str = ""
    audit_webhook: str = ""
    enabled: bool = False
    # Настроено ли из окружения: такие значения панель не дает стереть из
    # интерфейса, и человек должен понимать, почему поле "пустое, но работает".
    from_env: list[str] = []


class AlertsIn(BaseModel):
    telegram_token: str = Field(default=KEEP, max_length=200)
    telegram_chat: str = Field(default=KEEP, max_length=100)
    telegram_api: str = Field(default=KEEP, max_length=300)
    webhook: str = Field(default=KEEP, max_length=500)
    audit_webhook: str = Field(default=KEEP, max_length=500)


class TestOut(BaseModel):
    sent: bool
    errors: list[str] = []


class BackupOut(BaseModel):
    configured: bool
    at: str = ""
    ok: bool = False
    file: str = ""
    size: int = 0
    detail: str = ""
    age_hours: float = -1.0
    stale: bool = False


class EmergencyIn(BaseModel):
    # Пароль, которым запечатывается архив. В панели не сохраняется нигде.
    password: str = Field(min_length=MIN_ARCHIVE_PASSWORD, max_length=200)
    # Свой пароль от панели и код второго фактора: подтверждение, что архив
    # собирает человек, а не забытая в браузере вкладка.
    login_password: str = Field(min_length=1, max_length=200)
    otp: str = Field(default="", max_length=12)
    note: str = Field(default="", max_length=200)


def _tail(value: str) -> str:
    """Хвост секрета: достаточно, чтобы узнать свое значение, мало, чтобы им
    воспользоваться."""
    if not value:
        return ""
    return "•••" + value[-4:] if len(value) > 8 else "•••"


def _mask_url(value: str) -> str:
    """Адрес вебхука - тоже секрет: в нем обычно лежит одноразовый путь."""
    if not value:
        return ""
    head, _, rest = value.partition("://")
    host = rest.split("/")[0] if rest else ""
    # user:pass@host - тоже секрет, показываем только сам хост.
    host = host.rsplit("@", 1)[-1]
    return f"{head}://{host}/•••" if host else "•••"


def _alerts_out(cfg: dict) -> AlertsOut:
    settings = get_settings()
    from_env = [
        name
        for name, value in (
            ("telegram_token", settings.alert_telegram_token),
            ("telegram_chat", settings.alert_telegram_chat),
            ("telegram_api", settings.alert_telegram_api),
            ("webhook", settings.alert_webhook),
            ("audit_webhook", settings.audit_webhook),
        )
        if value
    ]
    return AlertsOut(
        telegram_token=_tail(cfg["telegram_token"]),
        telegram_chat=cfg["telegram_chat"],
        telegram_api=cfg["telegram_api"],
        webhook=_mask_url(cfg["webhook"]),
        audit_webhook=_mask_url(cfg["audit_webhook"]),
        enabled=alerts.enabled(cfg),
        from_env=from_env,
    )


@router.get("/alerts", response_model=AlertsOut)
async def get_alerts(_: OwnerUser, session: SessionDep) -> AlertsOut:
    return _alerts_out(await alerts.get_config(session))


@router.put("/alerts", response_model=AlertsOut)
async def put_alerts(body: AlertsIn, request: Request, user: OwnerUser, session: SessionDep):
    """Пустое поле оставляет прежнее значение, "-" очищает канал.

    Такой договор нужен из-за маскирования: интерфейс не знает полного токена и
    не может прислать его обратно, а "прислали пустое - значит стереть" однажды
    выключит оповещения при сохранении соседней настройки.
    """
    stored = await settings_store.get_many(session, "alert_")
    current = {
        "telegram_token": stored.get(alerts.TELEGRAM_TOKEN, ""),
        "telegram_chat": stored.get(alerts.TELEGRAM_CHAT, ""),
        "telegram_api": stored.get(alerts.TELEGRAM_API, ""),
        "webhook": stored.get(alerts.WEBHOOK, ""),
        "audit_webhook": await settings_store.get(session, alerts.AUDIT_WEBHOOK, ""),
    }
    new = dict(current)
    for field in new:
        incoming = getattr(body, field).strip()
        if incoming == KEEP:
            continue
        new[field] = "" if incoming == CLEAR else incoming

    # Адреса, по которым панель пойдет сама, проверяем до сохранения.
    for label, value in (
        ("Вебхук", new["webhook"]),
        ("Приёмник журнала", new["audit_webhook"]),
        ("Зеркало Bot API", new["telegram_api"]),
    ):
        try:
            await urlguard.check_outbound_url(value)
        except urlguard.UrlNotAllowed as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{label}: {exc}") from exc

    await alerts.set_config(session, **new)
    channels = []
    if new["telegram_token"] and new["telegram_chat"]:
        channels.append("telegram")
    if new["webhook"]:
        channels.append("вебхук")
    if new["audit_webhook"]:
        channels.append("копия журнала")
    await audit.record(
        session,
        actor=user.username,
        action="alerts_changed",
        # Через "; ", как остальные перечни журнала: английский интерфейс
        # переводит такие пункты по одному.
        detail="; ".join(channels) or "выключено",
        ip=peer_ip(request),
    )
    await session.commit()
    return _alerts_out(await alerts.get_config(session))


@router.post("/alerts/test", response_model=TestOut)
async def test_alerts(request: Request, user: OwnerUser, session: SessionDep) -> TestOut:
    cfg = await alerts.get_config(session)
    if not alerts.enabled(cfg):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Каналы оповещений не настроены")
    errors = await alerts.send(cfg, "🔔 Sekvyr: проверка связи", get_settings().panel_url)
    await audit.record(
        session,
        actor=user.username,
        action="alerts_test",
        detail="; ".join(errors) if errors else "доставлено",
        ip=peer_ip(request),
    )
    await session.commit()
    return TestOut(sent=not errors, errors=errors)


@router.get("/backup", response_model=BackupOut)
async def backup_state(_: OwnerUser) -> BackupOut:
    state = backups.read_state(get_settings())
    return BackupOut(**state.__dict__)


@router.post("/emergency")
async def emergency_archive(
    body: EmergencyIn,
    request: Request,
    user: OwnerUser,
    session: SessionDep,
    box: UnsealedBox,
) -> Response:
    """Собирает архив всех значений и отдает файл. Панель его у себя не хранит.

    Проверок здесь больше, чем где-либо еще, и это осознанно: одной удачной
    сессии владельца не должно хватать, чтобы вынести все хранилище одним
    запросом.
    """
    await confirm_password(
        session, user, body.login_password, request,
        message="Неверный пароль", code=status.HTTP_403_FORBIDDEN,
    )
    if user.totp_enabled:
        if not body.otp:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Нужен код второго фактора")
        if not await consume_totp(session, user, body.otp):
            await reauth_failed(session, user, request)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Неверный код второго фактора")

    snapshot = await emergency.collect(session, box)
    projects, envs, values = emergency.counts(snapshot)
    blob = emergency.pack(snapshot, body.password, note=body.note)

    detail = f"проектов {projects}, окружений {envs}, значений {values}"
    await audit.record(
        session,
        actor=user.username,
        action="emergency_archive",
        target=body.note,
        detail=detail,
        ip=peer_ip(request),
    )
    await session.commit()
    await alerts.notify(
        session,
        f"🧨 Sekvyr: {user.username} собрал аварийный архив — {detail}. "
        "Если это не запланированная выгрузка, разбирайтесь сейчас.",
    )
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="sekvyr-emergency.sealed"'},
    )
