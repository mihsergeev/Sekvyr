"""Корневой ключ: завести, отпереть, запереть, сменить.

Три вещи, которые нужно знать про этот роутер:

1. **Ключ и доли показываются до подтверждения настройки или ротации.**
   В базу они не пишутся, восстановить их из панели неоткуда.
2. **Запереть может владелец, отпереть - держатели долей.** Подача доли
   доступна с уровня ответственного: доли раздаются людям, а не ролям, но чтобы
   вообще дойти до этого маршрута, нужно войти в панель.
3. **Ротация корневого ключа не трогает значения.** Перекладываются только
   обертки ключей окружений - этих оберток десятки, а значений могут быть сотни
   тысяч.
"""

import asyncio
import hmac
import json
from pathlib import Path
from typing import Annotated

from anyio import CancelScope
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app import alerts, audit, crypto, envkeys, sealbox, shamir
from app.config import get_settings
from app.deps import BoxDep, MaintainerUser, OwnerUser, SessionDep, peer_ip
from app.models import User

router = APIRouter(prefix="/vault", tags=["vault"])


async def _key_file_lock(box: BoxDep):
    # Блокировка БД отпускается при коммите, а файл обновляется сразу после.
    async with box.key_file_lock:
        yield


KeyFileLock = Annotated[None, Depends(_key_file_lock)]


class StatusOut(BaseModel):
    initialized: bool
    sealed: bool
    mode: str
    # Чего ждут от панели после перезапуска: поднимется сама или будет ждать
    # ключ. Хранится с момента заведения сейфа.
    auto_unseal_intent: bool = False
    # Подходит ли настроенный ключ к текущему поколению сейфа.
    root_key_configured: bool = False
    # Куда панель может сохранить ключ, чтобы подниматься самой. Пусто - путь не
    # задан администратором сервера, и сохранять некуда.
    key_file_path: str = ""
    key_file_present: bool = False
    shares: int
    threshold: int
    # сколько долей уже подано в этом процессе - чтобы человек видел прогресс,
    # а не гадал, дошла ли его доля
    pending_shares: int
    root_generation: int


class InitIn(BaseModel):
    mode: str = Field(default=sealbox.MODE_SHARES)
    # Только для режима одного ключа: собираетесь ли класть его на сервер.
    # На саму криптографию не влияет - панель лишь запоминает намерение, чтобы
    # потом предупреждать о расхождении.
    auto_unseal: bool = False
    # Границы широкие намеренно: осмысленность набора проверяется в обработчике,
    # где можно объяснить человеку, что не так. Схема на неверном значении отдает
    # 422 со списком служебных объектов - из него в интерфейсе получается
    # "Ошибка HTTP 422", и человек остается наедине с формой.
    shares: int = Field(default=5, ge=1, le=16)
    threshold: int = Field(default=3, ge=1, le=16)


class InitOut(BaseModel):
    mode: str
    # только для режима долей
    shares: list[str] = []
    # только для режима переменной окружения: base64 корневого ключа
    root_key: str = ""
    warning: str


class PreparedKey(BaseModel):
    proof: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    root_key: str = Field(default="", max_length=512, repr=False)
    shares: list[Annotated[str, Field(max_length=512)]] = Field(default_factory=list, max_length=16, repr=False)


class InitCommitIn(InitIn):
    prepared: PreparedKey | None = Field(default=None, repr=False)


class PreparedInit(InitOut):
    proof: str = Field(repr=False)


class UnsealIn(BaseModel):
    share: str = Field(default="", max_length=512)
    root_key: str = Field(default="", max_length=512)


class UnsealOut(BaseModel):
    sealed: bool
    pending_shares: int
    threshold: int
    detail: str


class RotateOut(BaseModel):
    root_generation: int
    rewrapped_keys: int
    shares: list[str] = []
    root_key: str = ""


class PreparedRotation(PreparedKey):
    root_generation: int = Field(strict=True, ge=1)


async def _status(session: SessionDep, box) -> StatusOut:
    meta = await sealbox.read_meta(session)
    settings = get_settings()
    path = Path(settings.root_key_file) if settings.root_key_file else None
    key_file_present = path is not None and (path.exists() or sealbox.staged_key_file(path).exists())
    saved = sealbox.saved_root(settings.root_key, settings.root_key_file, meta)
    return StatusOut(
        initialized=meta.initialized,
        sealed=not box.unsealed,
        mode=meta.mode,
        auto_unseal_intent=meta.auto_unseal,
        root_key_configured=saved is not None and sealbox.check_root(saved, meta),
        key_file_path=settings.root_key_file,
        key_file_present=key_file_present,
        shares=meta.shares,
        threshold=meta.threshold,
        pending_shares=box.pending_shares,
        root_generation=meta.generation,
    )


@router.get("/status", response_model=StatusOut)
async def status_(_: MaintainerUser, session: SessionDep, box: BoxDep) -> StatusOut:
    return await _status(session, box)


def _validate_init(body: InitIn) -> None:
    if body.mode not in (sealbox.MODE_ENV, sealbox.MODE_SHARES):
        raise HTTPException(status.HTTP_409_CONFLICT, "неизвестный режим корневого ключа")
    if body.mode == sealbox.MODE_SHARES:
        if body.shares < 2:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Долей должно быть хотя бы две — иначе это просто копия ключа. "
                "Если ключ должен лежать целиком, выберите режим переменной окружения",
            )
        if body.threshold < 2:
            # Порог 1 выглядит как схема с долями, но ею не является: каждая доля
            # тогда равна всему ключу, и "ни у кого нет ключа целиком" перестает
            # быть правдой. Такое лучше называть своим именем, а не разрешать
            # молча под видом долей.
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Порог 1 означает, что каждая доля сама по себе открывает панель, "
                "то есть равна полному ключу. Возьмите порог от 2 или выберите "
                "режим переменной окружения",
            )
        if body.threshold > body.shares:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Порог ({body.threshold}) больше числа долей ({body.shares}) — "
                "отпереть панель было бы невозможно",
            )


def _init_material(body: InitIn, root: bytes) -> InitOut:
    if body.mode == sealbox.MODE_SHARES:
        return InitOut(
            mode=body.mode,
            shares=shamir.split(root, shares=body.shares, threshold=body.threshold),
            warning=(
                "Доли показываются один раз. Раздайте их разным людям и сохраните "
                "вне этой панели: восстановить их неоткуда, а без порога долей "
                "значения не расшифруются никогда."
            ),
        )
    return InitOut(
        mode=body.mode,
        root_key=sealbox.b64(root),
        warning=(
            "Ключ показывается один раз. Положите его в SEKVYR_ROOT_KEY_FILE "
            "(права 0400, вне тома с базой) и храните копию отдельно от бэкапов: "
            "потерянный ключ означает потерю всех значений."
        ),
    )


def _init_proof(user: User, body: InitIn, root: bytes, root_key: str, shares: list[str]) -> str:
    data = json.dumps(
        [user.id, user.username, body.mode, body.shares, body.threshold, body.auto_unseal,
         sealbox.b64(root), root_key, shares],
        separators=(",", ":"),
    ).encode("ascii")
    key = get_settings().jwt_secret.encode()
    return hmac.digest(key, b"sekvyr-vault-init-v1\0" + data, "sha256").hex()


@router.post("/init/prepare", response_model=PreparedInit)
async def prepare_init(body: InitIn, response: Response, user: OwnerUser, session: SessionDep) -> PreparedInit:
    _validate_init(body)
    if (await sealbox.read_meta(session)).initialized:
        raise HTTPException(status.HTTP_409_CONFLICT, "сейф уже заведён")
    root = crypto.new_key()
    material = _init_material(body, root)
    proof = _init_proof(user, body, root, material.root_key, material.shares)
    response.headers["Cache-Control"] = "no-store"
    return PreparedInit(**material.model_dump(), proof=proof)


@router.post("/init", response_model=InitOut)
async def init(
    body: InitCommitIn, request: Request, response: Response, user: OwnerUser, session: SessionDep, box: BoxDep
) -> InitOut:
    _validate_init(body)
    seal_epoch = box.seal_epoch
    await envkeys.lock_material(session, exclusive=True)
    meta = await sealbox.read_meta(session)
    response.headers["Cache-Control"] = "no-store"
    prepared = body.prepared
    shares_mode = body.mode == sealbox.MODE_SHARES
    shares = body.shares if shares_mode else 0
    threshold = body.threshold if shares_mode else 0
    auto_unseal = body.auto_unseal and not shares_mode
    if prepared is not None:
        root = _prepared_root(
            prepared, mode=body.mode, shares=shares, invalid_detail="Подготовленный ключ или доли повреждены",
        )
        proof = _init_proof(user, body, root, prepared.root_key, prepared.shares)
        if not hmac.compare_digest(proof, prepared.proof):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Подготовленный материал для настройки не совпадает")
        result = InitOut(mode=body.mode, warning="")
        if meta.initialized:
            if (
                meta.generation == 1 and meta.mode == body.mode and meta.shares == shares
                and meta.threshold == threshold and meta.auto_unseal == auto_unseal
                and sealbox.check_root(root, meta)
            ):
                return result
            raise HTTPException(status.HTTP_409_CONFLICT, "сейф уже заведён")
    else:
        if meta.initialized:
            raise HTTPException(status.HTTP_409_CONFLICT, "сейф уже заведён")
        root = crypto.new_key()
        result = _init_material(body, root)

    await sealbox.initialize(
        session, root=root, mode=body.mode, shares=shares, threshold=threshold, auto_unseal=auto_unseal,
    )
    await audit.record(
        session,
        actor=user.username,
        action="vault_initialized",
        detail=f"режим: {body.mode}" + (f", доли: {threshold} из {shares}" if shares_mode else ""),
        ip=peer_ip(request),
    )
    await session.commit()
    # При откате метаданных новый ключ не должен стать доступен для записи секретов.
    box.set_root_if_current(root, seal_epoch)
    return result


@router.post("/unseal", response_model=UnsealOut)
async def unseal(
    body: UnsealIn, request: Request, user: MaintainerUser, session: SessionDep, box: BoxDep
) -> UnsealOut:
    seal_epoch = box.seal_epoch
    await envkeys.lock_material(session, exclusive=True)
    meta = await sealbox.read_meta(session)
    if not meta.initialized:
        raise HTTPException(status.HTTP_409_CONFLICT, "Сейф ещё не заведён")
    if box.seal_epoch != seal_epoch:
        return _interrupted_unseal(meta)
    if box.unsealed:
        return UnsealOut(
            sealed=False, pending_shares=0, threshold=meta.threshold, detail="уже открыта"
        )

    if body.root_key:
        key = sealbox.root_from_env(body.root_key, "")
        if key is None or not sealbox.check_root(key, meta):
            await audit.record(
                session, actor=user.username, action="vault_unseal_failed", ip=peer_ip(request)
            )
            await session.commit()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Это не корневой ключ панели")
        await audit.record(
            session,
            actor=user.username,
            action="vault_unsealed",
            detail="корневым ключом",
            ip=peer_ip(request),
        )
        await session.commit()
        if not box.set_root_if_current(key, seal_epoch):
            return _interrupted_unseal(meta)
        await alerts.notify(
            session, f"🔓 Sekvyr: {user.username} открыл панель корневым ключом"
        )
        return UnsealOut(
            sealed=False, pending_shares=0, threshold=meta.threshold, detail="открыта"
        )

    if not body.share:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Введите долю или корневой ключ")
    try:
        box.add_share(body.share)
    except shamir.ShareError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # Достаточно ли долей - запоминаем ДО попытки собрать: если ключ не сошелся,
    # набор сбрасывается, и по нему уже не отличить "не хватает" от "среди долей
    # чужая". Первая версия этим и ошибалась: человек получал бодрое "доля
    # принята, нужно еще две" ровно в тот момент, когда все пошло не так.
    had_enough = box.pending_shares >= meta.threshold
    root = box.try_combine(meta)
    if root is None:
        remaining = max(meta.threshold - box.pending_shares, 0)
        if had_enough:
            # долей набралось достаточно, но ключ не сошелся: среди них чужая.
            # Набор при этом уже сброшен - начинать надо заново, и человек должен
            # это понимать, а не подавать четвертую долю в пустоту.
            await audit.record(
                session,
                actor=user.username,
                action="vault_unseal_failed",
                detail="долей достаточно, но ключ не сошёлся",
                ip=peer_ip(request),
            )
            await session.commit()
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Ключ не сошёлся: среди введённых долей есть чужая. Начните заново",
            )
        return UnsealOut(
            sealed=True,
            pending_shares=box.pending_shares,
            threshold=meta.threshold,
            detail=f"доля принята, нужно ещё {remaining}",
        )

    await audit.record(
        session,
        actor=user.username,
        action="vault_unsealed",
        detail=f"долями: {meta.threshold} из {meta.shares}",
        ip=peer_ip(request),
    )
    await session.commit()
    if not box.set_root_if_current(root, seal_epoch):
        return _interrupted_unseal(meta)
    await alerts.notify(
        session,
        f"🔓 Sekvyr: панель открыта долями ({meta.threshold} из {meta.shares}), "
        f"последнюю подал {user.username}",
    )
    return UnsealOut(
        sealed=False, pending_shares=0, threshold=meta.threshold, detail="открыта"
    )


def _interrupted_unseal(meta: sealbox.VaultMeta) -> UnsealOut:
    return UnsealOut(
        sealed=True, pending_shares=0, threshold=meta.threshold, detail="заперта во время отпирания"
    )


@router.post("/seal", response_model=StatusOut)
async def seal(
    request: Request, user: OwnerUser, session: SessionDep, box: BoxDep
) -> StatusOut:
    """Выбросить ключ из памяти. Кнопка "кажется, нас читают": значения
    перестают отдаваться немедленно, включая уже начатые сессии машин."""
    box.seal()
    await audit.record(
        session, actor=user.username, action="vault_sealed", ip=peer_ip(request)
    )
    await session.commit()
    await alerts.notify(
        session,
        f"🔒 Sekvyr: {user.username} запер панель — значения не выдаются никому, "
        "включая машины",
    )
    return await _status(session, box)


async def _commit_root_rotation(
    session: AsyncSession, box: sealbox.SealBox, new_root: bytes, key_path: Path | None
) -> None:
    try:
        await session.commit()
    except (Exception, asyncio.CancelledError):
        # Ошибка связи могла прийти уже после коммита. Сверяем с БД, прежде
        # чем решать, какой ключ оставить в памяти и что делать с файлом.
        try:
            await session.rollback()
            meta = await sealbox.read_meta(session)
        except Exception:
            box.seal()
            raise
        if not sealbox.check_root(new_root, meta):
            box.finish_rotation(new_root, committed=False)
            if key_path is not None:
                sealbox.discard_staged_key_file(key_path)
            raise
    box.finish_rotation(new_root, committed=True)
    if key_path is not None:
        # При отказе замены .new проверится при старте по маркеру в БД.
        # Ответ владельцу все равно должен содержать ключ.
        sealbox.publish_staged_key_file(key_path)


def _current_root(box: sealbox.SealBox, meta: sealbox.VaultMeta) -> bytes:
    if not box.unsealed:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Панель заперта: сначала введите текущий корневой ключ",
        )
    root = box.root()
    if not sealbox.check_root(root, meta):
        raise HTTPException(status.HTTP_409_CONFLICT, "Корневой ключ изменился: откройте сейф заново")
    return root


def _rotation_proof(old_root: bytes, generation: int, new_root: bytes, shares: list[str]) -> str:
    # The proof also binds the exact ordered list of prepared shares. Returning a
    # different share that reconstructs the same key with all the others would
    # otherwise risk making a smaller, threshold-sized subset unusable.
    data = (b"sekvyr-vault-root-rotation-v1\0" + str(generation).encode("ascii") + b"\0"
            + new_root + json.dumps(shares, separators=(",", ":")).encode("ascii"))
    return hmac.digest(old_root, data, "sha256").hex()


def _rotation_shares(root: bytes, meta: sealbox.VaultMeta) -> list[str]:
    return shamir.split(root, shares=meta.shares, threshold=meta.threshold) if meta.mode == sealbox.MODE_SHARES else []


def _prepared_root(
    body: PreparedKey, *, mode: str, shares: int,
    invalid_detail: str = "Ключ или доли для ротации повреждены",
) -> bytes:
    candidate = None
    if mode == sealbox.MODE_SHARES and not body.root_key and len(body.shares) == shares:
        try:
            candidate = shamir.combine(body.shares)
        except shamir.ShareError:
            pass
    elif mode == sealbox.MODE_ENV and not body.shares and body.root_key:
        candidate = sealbox.root_from_env(body.root_key, "")
    if candidate is None or len(candidate) != crypto.KEY_SIZE:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, invalid_detail)
    return candidate


@router.post("/rotate-root/prepare", response_model=PreparedRotation)
async def prepare_root_rotation(
    response: Response, _user: OwnerUser, session: SessionDep, box: BoxDep
) -> PreparedRotation:
    """Показывает материал заранее, чтобы его сохранили до необратимой смены."""
    meta = await sealbox.read_meta(session)
    if not meta.initialized:
        raise HTTPException(status.HTTP_409_CONFLICT, "Сейф ещё не заведён")
    old_root = _current_root(box, meta)
    new_root = crypto.new_key()
    shares = _rotation_shares(new_root, meta)
    response.headers["Cache-Control"] = "no-store"
    return PreparedRotation(
        root_generation=meta.generation,
        proof=_rotation_proof(old_root, meta.generation, new_root, shares),
        root_key="" if shares else sealbox.b64(new_root),
        shares=shares,
    )


@router.post("/rotate-root", response_model=RotateOut)
async def rotate_root(
    request: Request, response: Response, user: OwnerUser, session: SessionDep,
    box: BoxDep, _key_lock: KeyFileLock, body: PreparedRotation | None = None,
) -> RotateOut:
    """Новый корневой ключ. Значения не трогаются: перекладываются обертки
    ключей окружений, и все это одной транзакцией - половинчатого состояния,
    в котором часть оберток под новым ключом, а маркер под старым, не бывает."""
    await envkeys.lock_material(session, exclusive=True)
    meta = await sealbox.read_meta(session)
    if not meta.initialized:
        raise HTTPException(status.HTTP_409_CONFLICT, "Сейф ещё не заведён")
    response.headers["Cache-Control"] = "no-store"
    if body is not None and body.root_generation != meta.generation:
        if body.root_generation + 1 == meta.generation:
            # A lost reply can be retried even after restart. Matching the
            # verifier establishes that this exact prepared key was committed.
            if sealbox.check_root(_prepared_root(body, mode=meta.mode, shares=meta.shares), meta):
                return RotateOut(root_generation=meta.generation, rewrapped_keys=0)
        raise HTTPException(status.HTTP_409_CONFLICT, "Поколение изменилось: подготовьте смену ключа заново")

    old_root = _current_root(box, meta)
    configured_file = get_settings().root_key_file
    key_path = None
    if configured_file and sealbox.saved_root("", configured_file, meta) == old_root:
        key_path = Path(configured_file)
    if body is None:
        if key_path is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Подготовьте и сохраните новый ключ перед сменой")
        new_root = crypto.new_key()
        parts = _rotation_shares(new_root, meta)
    else:
        new_root = _prepared_root(body, mode=meta.mode, shares=meta.shares)
        proof = _rotation_proof(old_root, meta.generation, new_root, body.shares)
        if new_root == old_root or not hmac.compare_digest(proof, body.proof):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Подготовленный материал для ротации не совпадает")
        parts = []
    generation = meta.generation + 1
    count = await envkeys.rewrap_for_new_root(session, old_root, new_root, generation)
    await sealbox.rewrap_root(session, new_root, generation)

    await audit.record(
        session,
        actor=user.username,
        action="vault_root_rotated",
        detail=f"поколение {meta.generation} → {generation}, обёрток: {count}",
        ip=peer_ip(request),
    )
    # Если ключ запомнен на сервере, файл должен смениться вместе с ключом:
    # иначе после перезапуска панель не отопрется старым ключом из файла, а
    # новый, показанный один раз, мог никто не сохранить, и значения потеряны.
    # Новый файл пишется рядом до коммита и встает на место после него.
    if key_path is not None:
        # После предыдущей ошибки замены .new может быть единственной
        # сохраненной копией действующего ключа. Сначала публикуем ее.
        if sealbox.read_key_file(key_path) != old_root:
            staged = sealbox.staged_key_file(key_path)
            if sealbox.read_key_file(staged) != old_root:
                raise HTTPException(status.HTTP_409_CONFLICT, "Сохраненный ключ изменился во время ротации")
            sealbox.replace_key_file(staged, key_path)
        sealbox.stage_key_file(key_path, new_root)

    box.begin_rotation(old_root, new_root)
    completion = asyncio.create_task(_commit_root_rotation(session, box, new_root, key_path))
    # Дождаться результата даже после отмены запроса: его dependency иначе
    # закроет сессию, пока коммит еще идет, а память и файл останутся в переходе.
    cancelled = False
    with CancelScope(shield=True):
        while not completion.done():
            try:
                await asyncio.shield(completion)
            except asyncio.CancelledError:
                cancelled = True
    completion.result()
    if cancelled:
        raise asyncio.CancelledError

    return RotateOut(
        root_generation=generation,
        rewrapped_keys=count,
        shares=parts,
        root_key="" if body is not None or parts else sealbox.b64(new_root),
    )


# --- автоматическое отпирание ---------------------------------------------


class KeyFileOut(BaseModel):
    path: str
    present: bool
    detail: str


def _key_file(settings) -> Path:
    """Куда сохранять ключ. Путь задает администратор сервера переменной, а не
    панель: возможность записать корневой ключ куда угодно на диск - это не то,
    что стоит отдавать веб-интерфейсу."""
    if not settings.root_key_file:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Путь для ключа не задан: укажите SEKVYR_ROOT_KEY_FILE и перезапустите панель",
        )
    return Path(settings.root_key_file)


@router.post("/remember-key", response_model=KeyFileOut)
async def remember_key(
    request: Request, user: OwnerUser, session: SessionDep, box: BoxDep, _key_lock: KeyFileLock
) -> KeyFileOut:
    """Сохранить корневой ключ файлом, чтобы панель поднималась сама.

    Честная плата за удобство: после этого ключ лежит на сервере, и root на
    хосте означает доступ ко всем значениям. Ровно то, от чего защищает режим с
    ручным вводом - поэтому действие отдельное, доступно только владельцу и
    попадает в журнал.
    """
    await envkeys.lock_material(session, exclusive=True)
    if not box.unsealed:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Панель заперта: сначала введите ключ"
        )
    settings = get_settings()
    path = _key_file(settings)
    root = box.root()
    if not sealbox.check_root(root, await sealbox.read_meta(session)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Корневой ключ изменился: откройте сейф заново")
    if not box.unsealed:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Панель заперта: сначала введите ключ")
    path.parent.mkdir(parents=True, exist_ok=True)
    if sealbox.read_key_file(path) == root:
        sealbox.discard_staged_key_file(path)
    else:
        if sealbox.read_key_file(sealbox.staged_key_file(path)) != root:
            sealbox.stage_key_file(path, root)
        sealbox.publish_staged_key_file(path)
    await audit.record(
        session,
        actor=user.username,
        action="vault_key_remembered",
        detail=str(path),
        ip=peer_ip(request),
    )
    await session.commit()
    return KeyFileOut(
        path=str(path),
        present=True,
        detail="Панель будет отпираться сама при запуске",
    )


@router.post("/forget-key", response_model=KeyFileOut)
async def forget_key(
    request: Request, user: OwnerUser, session: SessionDep, _key_lock: KeyFileLock
) -> KeyFileOut:
    """Убрать сохраненный ключ: панель снова будет ждать ручного ввода."""
    await envkeys.lock_material(session, exclusive=True)
    settings = get_settings()
    path = _key_file(settings)
    existed = sealbox.forget_key_files(path)
    await audit.record(
        session,
        actor=user.username,
        action="vault_key_forgotten",
        detail=str(path),
        ip=peer_ip(request),
    )
    await session.commit()
    return KeyFileOut(
        path=str(path),
        present=False,
        detail="Ключ удалён" if existed else "Файла и так не было",
    )
