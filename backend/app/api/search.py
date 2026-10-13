"""Поиск ключа по всем проектам сразу.

Вопрос "а где вообще лежит SMTP_PASSWORD" задают чаще, чем кажется: ключ с
одинаковым именем живет в трех окружениях, а помнить, в каком из них правильный,
человек не обязан. Раньше на него отвечали обходом проектов руками.

Значения поиск не отдает и отдавать не должен: он говорит, где искать, а читать
значение человек идет туда, где на это есть право.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app import access
from app.deps import CurrentUser, SessionDep
from app.models import Environment, Project, Secret

router = APIRouter(prefix="/search", tags=["search"])


class HitOut(BaseModel):
    group_slug: str
    project_slug: str
    project_title: str
    environment: str
    path: str
    name: str


@router.get("", response_model=list[HitOut])
async def search_secrets(
    user: CurrentUser,
    session: SessionDep,
    q: str = Query(min_length=2, max_length=100),
    limit: int = Query(default=30, ge=1, le=100),
) -> list[HitOut]:
    needle = q.strip().lower()
    if not needle:
        return []

    # Экранируем подстановочные знаки: "100%" ищут буквально.
    escaped = needle.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    pattern = f"%{escaped}%"

    query = (
        select(Secret, Environment, Project)
        .join(Environment, Environment.id == Secret.environment_id)
        .join(Project, Project.id == Environment.project_id)
        .where(
            Secret.deleted.is_(False),
            func.lower(Secret.name).like(pattern, escape="!"),
        )
        .order_by(Secret.name, Project.slug, Secret.id)
    )

    # Права считаем по разу загруженным политикам: иначе на каждую строку
    # уходил бы отдельный запрос в базу.
    policies = [] if user.role == access.OWNER else await access.policies_for(session, user)
    now = datetime.now(timezone.utc)

    async def pages():
        # Страницами, пока не наберется видимое: один запрос "с запасом в 20
        # раз" терял совпадения, если перед ними стояли сотни чужих. Предел на
        # число страниц - чтобы поиск не перебирал всю базу.
        page = max(limit * 20, 200)
        for number in range(50):
            rows = (await session.execute(query.offset(number * page).limit(page))).all()
            for row in rows:
                yield row
            if len(rows) < page:
                return

    out: list[HitOut] = []
    async for secret, environment, project in pages():
        scope = access.Scope(
            project_id=project.id,
            environment_id=environment.id,
            path=secret.path,
        )
        if user.role != access.OWNER and not access.decide(policies, user, "list", scope, now):
            continue
        out.append(
            HitOut(
                group_slug=project.group_slug,
                project_slug=project.slug,
                project_title=project.title,
                environment=environment.name,
                path=secret.path,
                name=secret.name,
            )
        )
        if len(out) >= limit:
            break
    return out
