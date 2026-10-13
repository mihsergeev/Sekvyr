"""Корневой ключ: завести, отпереть, запереть, сменить.

Три вещи, которые нужно знать про этот роутер:

1. **Ключ и доли показываются ровно один раз** - в ответе на инициализацию или
   ротацию. В базу они не пишутся, повторно узнать их неоткуда, и это не
   недоработка, а все содержание схемы.
2. **Запереть может владелец, отпереть - держатели долей.** Подача доли
   доступна с уровня ответственного: доли раздаются людям, а не ролям, но чтобы
   вообще дойти до этого маршрута, нужно войти в панель.
3. **Ротация корневого ключа не трогает значения.** Перекладываются только
   обертки ключей окружений - этих оберток десятки, а значений могут быть сотни
   тысяч.
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

import os

from app import alerts, audit, crypto, envkeys, sealbox, shamir
from app.config import get_settings
from app.deps import BoxDep, MaintainerUser, OwnerUser, SessionDep, peer_ip

router = APIRouter(prefix="/vault", tags=["vault"])


class StatusOut(BaseModel):
    initialized: bool
    sealed: bool
    mode: str
    # Чего ждут от панели после перезапуска: поднимется сама или будет ждать
    # ключ. Хранится с момента заведения сейфа.
    auto_unseal_intent: bool = False
    # Задан ли корневой ключ в окружении СЕЙЧАС. Не сам ключ, а факт: по нему
    # видно расхождение с намерением до того, как оно всплывет при перезапуске.
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


async def _status(session: SessionDep, box) -> StatusOut:
    meta = await sealbox.read_meta(session)
    settings = get_settings()
    key_file_present = bool(settings.root_key_file) and Path(settings.root_key_file).exists()
    return StatusOut(
        initialized=meta.initialized,
        sealed=not box.unsealed,
        mode=meta.mode,
        auto_unseal_intent=meta.auto_unseal,
        # Путь к файлу без самого файла (ключ забыли кнопкой) - ключа нет:
        # раньше баннер после "забыть" говорил, что ключ лежит на сервере, и
        # молчал о том, что панель после перезапуска окажется запертой.
        root_key_configured=bool(settings.root_key) or key_file_present,
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


@router.post("/init", response_model=InitOut)
async def init(
    body: InitIn, request: Request, user: OwnerUser, session: SessionDep, box: BoxDep
) -> InitOut:
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
    try:
        root, parts = await sealbox.initialize(
            session,
            mode=body.mode,
            shares=body.shares,
            threshold=body.threshold,
            auto_unseal=body.auto_unseal,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    # Панель сразу открыта: заводить сейф и тут же требовать доли было бы
    # бессмысленным обрядом - ключ и так в памяти этого процесса.
    box.set_root(root)
    await audit.record(
        session,
        actor=user.username,
        action="vault_initialized",
        detail=f"режим: {body.mode}"
        + (f", доли: {body.threshold} из {body.shares}" if parts else ""),
        ip=peer_ip(request),
    )
    await session.commit()

    if parts:
        return InitOut(
            mode=body.mode,
            shares=parts,
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


@router.post("/unseal", response_model=UnsealOut)
async def unseal(
    body: UnsealIn, request: Request, user: MaintainerUser, session: SessionDep, box: BoxDep
) -> UnsealOut:
    meta = await sealbox.read_meta(session)
    if not meta.initialized:
        raise HTTPException(status.HTTP_409_CONFLICT, "Сейф ещё не заведён")
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
        box.set_root(key)
        await audit.record(
            session,
            actor=user.username,
            action="vault_unsealed",
            detail="корневым ключом",
            ip=peer_ip(request),
        )
        await session.commit()
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

    box.set_root(root)
    await audit.record(
        session,
        actor=user.username,
        action="vault_unsealed",
        detail=f"долями: {meta.threshold} из {meta.shares}",
        ip=peer_ip(request),
    )
    await session.commit()
    await alerts.notify(
        session,
        f"🔓 Sekvyr: панель открыта долями ({meta.threshold} из {meta.shares}), "
        f"последнюю подал {user.username}",
    )
    return UnsealOut(
        sealed=False, pending_shares=0, threshold=meta.threshold, detail="открыта"
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


@router.post("/rotate-root", response_model=RotateOut)
async def rotate_root(
    request: Request, user: OwnerUser, session: SessionDep, box: BoxDep
) -> RotateOut:
    """Новый корневой ключ. Значения не трогаются: перекладываются обертки
    ключей окружений, и все это одной транзакцией - половинчатого состояния,
    в котором часть оберток под новым ключом, а маркер под старым, не бывает."""
    meta = await sealbox.read_meta(session)
    if not meta.initialized:
        raise HTTPException(status.HTTP_409_CONFLICT, "Сейф ещё не заведён")
    if not box.unsealed:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Панель заперта: сначала введите текущий корневой ключ",
        )

    old_root = box.root()
    new_root = crypto.new_key()
    generation = meta.generation + 1
    count = await envkeys.rewrap_for_new_root(session, old_root, new_root, generation)
    await sealbox.rewrap_root(session, new_root, generation)

    parts = (
        shamir.split(new_root, shares=meta.shares, threshold=meta.threshold)
        if meta.mode == sealbox.MODE_SHARES
        else []
    )
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
    key_path = Path(get_settings().root_key_file) if get_settings().root_key_file else None
    staged = None
    if key_path is not None and key_path.exists():
        staged = key_path.with_name(key_path.name + ".new")
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(sealbox.b64(new_root))
    # Новый ключ - в память до коммита. После коммита блокировка ключевого
    # материала уже отпущена, и новое окружение, заведенное до замены ключа в
    # памяти, обертывалось бы прежним: его значения не читались бы никогда. До
    # коммита новые ключи окружений ждут эту блокировку (envkeys.lock_material).
    # Если панель заперли, пока шла переобертка, запертой она и остается:
    # иначе "запереть" молча отменялось бы, а значения снова отдавались.
    sealed_meanwhile = not box.unsealed or box.root() != old_root
    if not sealed_meanwhile:
        box.set_root(new_root)
    try:
        await session.commit()
    except Exception:
        # Упал коммит - в базе прежний ключ, и в памяти должен быть он же.
        if box.unsealed and box.root() == new_root:
            box.set_root(old_root)
        if staged is not None:
            staged.unlink(missing_ok=True)
        raise
    if staged is not None:
        os.replace(staged, key_path)

    return RotateOut(
        root_generation=generation,
        rewrapped_keys=count,
        shares=parts,
        root_key="" if parts else sealbox.b64(new_root),
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
    request: Request, user: OwnerUser, session: SessionDep, box: BoxDep
) -> KeyFileOut:
    """Сохранить корневой ключ файлом, чтобы панель поднималась сама.

    Честная плата за удобство: после этого ключ лежит на сервере, и root на
    хосте означает доступ ко всем значениям. Ровно то, от чего защищает режим с
    ручным вводом - поэтому действие отдельное, доступно только владельцу и
    попадает в журнал.
    """
    if not box.unsealed:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Панель заперта: сначала введите ключ"
        )
    settings = get_settings()
    path = _key_file(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Создаем файл сразу с правами 0600, а не пишем и потом исправляем: между
    # этими шагами он был бы читаем всем, кто окажется рядом.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(sealbox.b64(box.root()))
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
    request: Request, user: OwnerUser, session: SessionDep
) -> KeyFileOut:
    """Убрать сохраненный ключ: панель снова будет ждать ручного ввода."""
    settings = get_settings()
    path = _key_file(settings)
    existed = path.exists()
    if existed:
        path.unlink()
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
