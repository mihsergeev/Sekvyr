"""Журнал: чтение и проверка целостности.

Журнал только читается. Маршрутов, которые правят или чистят записи, здесь нет
и не появится: журнал, который умеет редактировать сама панель, ничего не
доказывает. Копия записей уезжает на внешний приемник - см. `app/audit_ship.py`.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app import alerts
from app import audit as audit_log
from app.audit import to_utc
from app.deps import MaintainerUser, OwnerUser, SessionDep
from app.models import AuditLog
from sqlalchemy import ColumnElement, desc, func, or_, select

router = APIRouter(prefix="/audit", tags=["audit"])


class EntryOut(BaseModel):
    id: int
    ts: str
    actor: str
    action: str
    target: str
    detail: str
    ip: str


class PageOut(BaseModel):
    total: int
    entries: list[EntryOut]


class VerifyOut(BaseModel):
    ok: bool
    broken_id: int | None = None
    # Сколько записей не сошлись всего: одна строка - это правка, много - это
    # переписанный журнал, и разговор в этих случаях разный.
    breaks: int = 0


def _search(q: str, q_actions: list[str]) -> list[ColumnElement[bool]]:
    """Условие поиска: по видимым полям записи и по кодам действий.

    Коды передает панель: в базе лежит `secret_written`, а человек ищет "записано
    значение". Русские названия живут в интерфейсе, поэтому он и присылает
    подходящие коды вместе со строкой.
    """
    needle = q.strip().lower()
    if not needle and not q_actions:
        return []

    checks: list[ColumnElement[bool]] = []
    if needle:
        # Экранируем подстановочные знаки: искать "100%" человек будет буквально,
        # а не "что угодно после 100".
        escaped = needle.replace("!", "!!").replace("%", "!%").replace("_", "!_")
        pattern = f"%{escaped}%"
        for column in (
            AuditLog.actor,
            AuditLog.action,
            AuditLog.target,
            AuditLog.detail,
            AuditLog.ip,
        ):
            checks.append(func.lower(column).like(pattern, escape="!"))
    if q_actions:
        checks.append(AuditLog.action.in_(q_actions[:40]))
    return [or_(*checks)]


def _filters(actions: list[str], days: int) -> list[ColumnElement[bool]]:
    """Отбор, а не поиск: тип события и период сужают выдачу, а не расширяют.

    Поэтому они складываются с поиском через И: "отказы" плюс "за неделю" плюс
    "про этот ключ" - это одно требование, а не три варианта.
    """
    checks: list[ColumnElement[bool]] = []
    if actions:
        checks.append(AuditLog.action.in_(actions[:60]))
    if days > 0:
        checks.append(AuditLog.ts >= datetime.now(timezone.utc) - timedelta(days=days))
    return checks


@router.get("", response_model=PageOut)
async def list_entries(
    _: MaintainerUser,
    session: SessionDep,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    q: str = Query(default="", max_length=200),
    q_action: list[str] = Query(default=[]),
    action: list[str] = Query(default=[]),
    days: int = Query(default=0, ge=0, le=3660),
) -> PageOut:
    where = _search(q, q_action) + _filters(action, days)
    total = int(
        await session.scalar(select(func.count()).select_from(AuditLog).where(*where)) or 0
    )
    rows = await session.scalars(
        select(AuditLog).where(*where).order_by(desc(AuditLog.id)).limit(limit).offset(offset)
    )
    return PageOut(
        total=total,
        entries=[
            EntryOut(
                id=r.id,
                # ВСЕГДА с зоной: SQLite отдает datetime без нее, и такую строку
                # браузер разбирает как местное время - журнал показывал бы
                # события со сдвигом на часовой пояс и выглядел бы правдоподобно.
                ts=to_utc(r.ts).isoformat() if r.ts else "",
                actor=r.actor,
                action=r.action,
                target=r.target,
                detail=r.detail,
                ip=r.ip,
            )
            for r in rows
        ],
    )


@router.get("/verify", response_model=VerifyOut)
async def verify_chain(_: OwnerUser, session: SessionDep) -> VerifyOut:
    """Пересчитывает всю цепочку и говорит, с какой записи она разошлась.

    Проверка идет по всем записям сразу: на нынешних объемах это дешево, а
    выборочная проверка "последних N" пропустила бы ровно то, ради чего цепочка
    и заводилась - правку в середине.
    """
    ok, broken, breaks = await audit_log.verify(session)
    if not ok:
        # Разошедшаяся цепочка - не "результат проверки", а происшествие: кто-то
        # правил журнал в обход панели. Оповещение уходит сразу, потому что
        # человек, открывший эту страницу, может оказаться не тем, кому об этом
        # надо знать.
        await alerts.notify(
            session,
            f"🚨 Sekvyr: журнал не сходится начиная с записи №{broken} "
            f"(расхождений: {breaks}) — записи правили в обход панели",
        )
    return VerifyOut(ok=ok, broken_id=broken, breaks=breaks)
