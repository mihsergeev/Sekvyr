"""Перенос секретов из Infisical и Vault: сначала предпросмотр, потом запись.

Два шага здесь не формальность. Импорт чужого набора ключей поверх рабочего
окружения - самый быстрый способ незаметно испортить прод, поэтому панель
сначала показывает, что она увидела на той стороне и что случится с каждым
ключом, и только потом переносит. По умолчанию существующие значения не
трогаются вовсе.

Реквизиты источника живут внутри запроса и никуда не сохраняются: панель не
должна становиться вторым местом, где лежит доступ к старому хранилищу. Поэтому
и предпросмотр, и перенос ходят в источник заново - это дешевле, чем хранить
чужой токен "на пару минут".
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app import access, audit, importers, secrets_store, urlguard
from app.api.secrets import refuse_below_threshold
from app.deps import MaintainerUser, SessionDep, UnsealedBox, peer_ip
from app.models import Environment

router = APIRouter(prefix="/migrate", tags=["migrate"])

INFISICAL = "infisical"
VAULT = "vault"
MAX_ITEMS = 5000


class SourceIn(BaseModel):
    """Откуда берем. Реквизиты не сохраняются: они живут ровно один запрос."""

    source: str = Field(pattern=f"^({INFISICAL}|{VAULT})$")
    url: str = Field(min_length=1, max_length=300)
    # Infisical: пара машинной личности (Universal Auth).
    client_id: str = Field(default="", max_length=200)
    client_secret: str = Field(default="", max_length=300)
    workspace_id: str = Field(default="", max_length=120)
    environment: str = Field(default="", max_length=64)
    secret_path: str = Field(default="/", max_length=200)
    # Vault: токен и раздел KV.
    token: str = Field(default="", max_length=500)
    mount: str = Field(default="secret", max_length=120)
    path: str = Field(default="", max_length=200)


class PreviewIn(SourceIn):
    environment_id: int
    # Куда класть то, что на той стороне лежало в корне.
    target_path: str = Field(default="/", max_length=200)


class ApplyIn(PreviewIn):
    # По умолчанию существующее не трогаем: молча переписанный прод - это то,
    # ради чего здесь вообще два шага.
    overwrite: bool = False


class RowOut(BaseModel):
    path: str
    name: str
    # "создать", "обновить" или "совпадает" - что случится при переносе.
    action: str
    # Длина значения вместо самого значения: предпросмотр не должен
    # превращаться в способ посмотреть чужие секреты мимо прав на чтение.
    size: int


class PreviewOut(BaseModel):
    total: int
    create: int
    update: int
    same: int
    note: str = ""
    rows: list[RowOut] = []


class ApplyOut(BaseModel):
    created: int
    updated: int
    skipped: list[str] = []


class ProjectsIn(BaseModel):
    url: str = Field(min_length=1, max_length=300)
    client_id: str = Field(min_length=1, max_length=200)
    client_secret: str = Field(min_length=1, max_length=300)
    # Куда собираются переносить: право на поход в чужую сеть то же, что у
    # самого переноса.
    environment_id: int


class ProjectOut(BaseModel):
    id: str
    name: str
    environments: list[str] = []


async def _guard(session: SessionDep, user, environment_id: int) -> Environment:
    env = await session.get(Environment, environment_id)
    if env is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Окружение не найдено")
    await access.require(
        session,
        user,
        access.WRITE,
        access.Scope(project_id=env.project_id, environment_id=env.id, path="/"),
    )
    if await secrets_store.is_e2e(session, env.id):
        # Проверка до похода в источник: иначе панель сначала вытянула бы
        # открытые значения к себе и только потом отказалась бы их класть.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "у проекта шифрование в браузере: перенести в него открытые значения "
            "нельзя, запечатать их некому",
        )
    return env


async def _readable(session, user, env: Environment, folder: str) -> bool:
    """Можно ли человеку знать, совпадает ли значение с тем, что уже лежит.

    Перенос требует только права записи. Без этой проверки ответ "совпадает"
    превращал предпросмотр в способ угадывать чужое значение: источник человек
    задает сам, и каждая догадка проверялась бы молча, без записи в журнал.
    """
    return await access.allowed(
        session,
        user,
        access.READ,
        access.Scope(project_id=env.project_id, environment_id=env.id, path=folder),
    )


def _folder(target_path: str, item_path: str) -> str:
    """Куда ляжет ключ: путь источника внутрь выбранной папки панели."""
    base = secrets_store.normalize_path(target_path or "/")
    tail = secrets_store.normalize_path(item_path or "/")
    if tail == "/":
        return base
    return secrets_store.normalize_path(base.rstrip("/") + tail)


async def _source(url: str) -> None:
    try:
        await urlguard.check_source_url(url)
    except urlguard.UrlNotAllowed as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


async def _fetch(body: SourceIn) -> importers.Fetched:
    await _source(body.url)
    try:
        if body.source == INFISICAL:
            if not (body.client_id and body.client_secret):
                raise importers.SourceError("нужны идентификатор и секрет машинной личности")
            if not (body.workspace_id and body.environment):
                raise importers.SourceError("нужны проект и окружение Infisical")
            token = await importers.infisical_login(
                body.url, body.client_id, body.client_secret
            )
            return await importers.infisical_fetch(
                body.url,
                token,
                workspace_id=body.workspace_id,
                environment=body.environment,
                secret_path=body.secret_path or "/",
            )
        if not body.token:
            raise importers.SourceError("нужен токен Vault")
        return await importers.vault_fetch(
            body.url, body.token, mount=body.mount, path=body.path
        )
    except importers.SourceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/infisical/projects", response_model=list[ProjectOut])
async def infisical_projects(
    body: ProjectsIn, user: MaintainerUser, session: SessionDep
) -> list[ProjectOut]:
    """Проекты Infisical, которые видит эта личность: чтобы не искать
    идентификатор проекта руками в чужом интерфейсе."""
    await _guard(session, user, body.environment_id)
    await _source(body.url)
    try:
        token = await importers.infisical_login(body.url, body.client_id, body.client_secret)
        rows = await importers.infisical_projects(body.url, token)
    except importers.SourceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return [ProjectOut(**row) for row in rows]


_ABSENT = object()


async def _effective_value(session, box, env_id: int, folder: str, name: str):
    """Что окружение отдает по этому ключу сейчас, с учетом наследования, или
    _ABSENT. Как у импорта: перенос без перезаписи не должен ставить свое
    значение поверх родительского, а ключ, у которого есть только ожидающая
    правка, действующего значения не имеет."""
    found = await secrets_store.resolve(session, env_id, folder, name)
    if found is None:
        return _ABSENT
    try:
        return await secrets_store.read_value(session, box, found[0])
    except secrets_store.SecretNotFound:
        return _ABSENT


@router.post("/preview", response_model=PreviewOut)
async def preview(
    body: PreviewIn, user: MaintainerUser, session: SessionDep, box: UnsealedBox
) -> PreviewOut:
    """Что панель увидела на той стороне и что случится с каждым ключом."""
    env = await _guard(session, user, body.environment_id)
    fetched = await _fetch(body)
    if len(fetched.items) > MAX_ITEMS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"на той стороне {len(fetched.items)} ключей — это больше предела "
            f"({MAX_ITEMS}); сузьте путь",
        )

    rows: list[RowOut] = []
    create = update = same = 0
    for item in fetched.items:
        folder = _folder(body.target_path, item.path)
        current = await _effective_value(session, box, body.environment_id, folder, item.name)
        if current is _ABSENT:
            action = "создать"
            create += 1
        elif await _readable(session, user, env, folder) and current == item.value:
            action = "совпадает"
            same += 1
        else:
            action = "обновить"
            update += 1
        rows.append(RowOut(path=folder, name=item.name, action=action, size=len(item.value)))

    return PreviewOut(
        total=len(rows),
        create=create,
        update=update,
        same=same,
        note=fetched.note,
        rows=sorted(rows, key=lambda r: (r.path, r.name)),
    )


@router.post("/apply", response_model=ApplyOut)
async def apply(
    body: ApplyIn,
    request: Request,
    user: MaintainerUser,
    session: SessionDep,
    box: UnsealedBox,
) -> ApplyOut:
    """Перенос. Значения в журнал не попадают - только сколько их было."""
    env = await _guard(session, user, body.environment_id)
    await refuse_below_threshold(session, user, env)
    fetched = await _fetch(body)
    if len(fetched.items) > MAX_ITEMS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "слишком много ключей — сузьте путь")
    # Источник раскладывает ключи по папкам сам - право записи нужно на каждую,
    # как у импорта: иначе запрет на папку обходился бы переносом.
    for folder in sorted({_folder(body.target_path, item.path) for item in fetched.items}):
        await access.require(
            session,
            user,
            access.WRITE,
            access.Scope(project_id=env.project_id, environment_id=env.id, path=folder),
        )

    created = updated = 0
    skipped: list[str] = []
    # Как у импорта: "уже есть" решается под блокировкой, иначе ключ, заведенный
    # руками, пока перенос ждал, перезаписывался переносом без перезаписи.
    await secrets_store.lock_env(session, body.environment_id)
    for item in fetched.items:
        folder = _folder(body.target_path, item.path)
        current = await _effective_value(session, box, body.environment_id, folder, item.name)
        alive = current is not _ABSENT
        if alive and await _readable(session, user, env, folder) and current == item.value:
            # Одинаковое значение - не повод плодить версию: история должна
            # показывать изменения, а не факт запуска переноса. И в пропущенные
            # такой ключ не идет: "пропущено 40" о совпадающих значениях звучит
            # тревожно ровно там, где ничего не произошло.
            continue
        if alive and not body.overwrite:
            skipped.append(item.name)
            continue
        try:
            await secrets_store.set_value(
                session,
                box,
                env_id=body.environment_id,
                path=folder,
                name=item.name,
                value=item.value,
                author=user.username,
                comment=f"перенос из {body.source}",
            )
        except secrets_store.BadName as exc:
            # В Vault имя поля и путь могут быть любыми. Один такой ключ не
            # повод ронять весь перенос: он попадает в пропущенные с
            # объяснением, и объяснение говорит, что именно не так.
            what = "недопустимая папка" if str(exc).startswith("папка") else "недопустимое имя"
            skipped.append(f"{item.name} ({what})")
            continue
        except secrets_store.SealedValueRequired as exc:
            # Перенести открытые значения в проект с шифрованием в браузере
            # нельзя: их некому запечатать - ключа проекта у сервера нет.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        if alive:
            updated += 1
        else:
            created += 1

    await audit.record(
        session,
        actor=user.username,
        action="secrets_migrated",
        target=str(env.id),
        detail=f"из {body.source}: создано {created}, обновлено {updated}, "
        f"пропущено {len(skipped)}",
        ip=peer_ip(request),
    )
    await session.commit()
    return ApplyOut(created=created, updated=updated, skipped=sorted(skipped)[:50])
