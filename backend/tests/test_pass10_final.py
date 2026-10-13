"""Финальное ревью перед 1.0.0: временные права, чтение пачкой, удаление по
ходу запроса, оповещения после доставки, даты."""

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select, update

from app import secrets_store
from app.models import MachineIdentity, Policy, Secret, SecretVersion
from tests.conftest import login
from tests.test_pass8b_backend import PASS, _pol, _user
from tests.test_pass9_backend import Gate, _bearer, _gated, _machine, _put, gate_async, run_safely

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


def _app(client):
    return client._transport.app


async def _policy(client, h, body):
    res = await client.post("/api/policies", headers=h, json=body)
    assert res.status_code == 201, res.text
    return res.json()


async def _lead(client, h, env_id, until, name="lead"):
    uid = await _user(client, h, name, "maintainer")
    await _policy(client, h, {"subject_type": "user", "subject_id": uid, "environment_id": env_id, "path_prefix": "/",
                              "actions": ["list", "read"], "effect": "allow", "expires_at": until})
    return uid, await login(client, name, PASS)


async def _machine_policies(client, machine_id):
    async with _app(client).state.session_factory() as session:
        return list(await session.scalars(select(Policy).where(Policy.subject_type == "machine", Policy.subject_id == machine_id)))


# --- 1. временные права ----------------------------------------------------------


async def test_reattach_after_expired_grant(client: httpx.AsyncClient, owner_headers, env_id):
    """Временный ответственный подключил машину (право до T), T прошло.
    Владелец жмет "подключить" снова: ожидаем, что право вернется."""
    h = owner_headers
    await _put(client, h, env_id, "A", "1")
    _uid, lead = await _lead(client, h, env_id, (NOW() + timedelta(days=1)).isoformat())
    box = (await client.post("/api/machines", headers=lead, json={"name": "box", "description": ""})).json()
    res = await client.post(f"/api/machines/{box['id']}/attach", headers=lead, json={"environment_id": env_id})
    assert res.status_code == 200 and res.json()["granted"], res.text
    # Время прошло: право машины истекло.
    async with _app(client).state.session_factory() as session:
        await session.execute(update(Policy).where(Policy.subject_type == "machine", Policy.subject_id == box["id"])
                              .values(expires_at=NOW() - timedelta(minutes=1)))
        await session.commit()
    res = await client.post(f"/api/machines/{box['id']}/attach", headers=h, json={"environment_id": env_id})
    _ = ("owner re-attach:", res.status_code, res.json())
    agent = await _bearer(client, box)
    read = await client.get("/api/v1/machine/secrets", headers=agent, params={"project": "billing", "env": "prod"})
    _ = ("agent read after owner re-attach:", read.status_code, read.text[:200])
    assert read.status_code == 200, "владелец подключил машину, а она окружение не читает"


async def test_lead_cannot_manage_a_machine_that_dies_before_him(client: httpx.AsyncClient, owner_headers, env_id):
    """Машина владельца со сроком через сутки и бессрочной политикой. У
    ответственного prod на неделю. Машина умрет раньше его права: перевыпуск
    секрета и сокращение срока его права не продлевают."""
    h = owner_headers
    m = (await client.post("/api/machines", headers=h, json={"name": "ci", "description": "",
                                                             "expires_at": (NOW() + timedelta(days=1)).isoformat()})).json()
    await _policy(client, h, {"subject_type": "machine", "subject_id": m["id"], "environment_id": env_id,
                              "path_prefix": "/", "actions": ["read", "list"], "effect": "allow"})
    _uid, lead = await _lead(client, h, env_id, (NOW() + timedelta(days=7)).isoformat())
    res = await client.post(f"/api/machines/{m['id']}/secret", headers=lead)
    _ = ("rotate secret:", res.status_code, res.text[:150])
    res2 = await client.patch(f"/api/machines/{m['id']}", headers=lead,
                              json={"expires_at": (NOW() + timedelta(hours=2)).isoformat()})
    _ = ("shorten expiry:", res2.status_code, res2.text[:150])
    assert res.status_code == 200 and res2.status_code == 200


async def test_lead_cannot_set_a_deadline_on_a_permanent_machine(client: httpx.AsyncClient, owner_headers, env_id):
    """Бессрочная машина, ответственный на неделю ставит ей срок через сутки
    (то есть внутри своего окна)."""
    h = owner_headers
    m = (await client.post("/api/machines", headers=h, json={"name": "ci", "description": ""})).json()
    await _policy(client, h, {"subject_type": "machine", "subject_id": m["id"], "environment_id": env_id,
                              "path_prefix": "/", "actions": ["read", "list"], "effect": "allow"})
    _uid, lead = await _lead(client, h, env_id, (NOW() + timedelta(days=7)).isoformat())
    res = await client.patch(f"/api/machines/{m['id']}", headers=lead,
                             json={"expires_at": (NOW() + timedelta(days=1)).isoformat()})
    _ = ("set deadline:", res.status_code, res.text[:150])
    assert res.status_code == 200


async def test_until_with_group_and_personal(client: httpx.AsyncClient, owner_headers, env_id):
    """Группа до T1, лично до T2>T1: машина до T2. Лично / до T1 + /db бессрочно: до T1."""
    h = owner_headers
    t1, t2 = NOW() + timedelta(days=1), NOW() + timedelta(days=3)
    uid, lead = await _lead(client, h, env_id, t2.isoformat())
    g = await client.post("/api/groups", headers=h, json={"name": "ops"})
    if g.status_code in (200, 201):
        gid = g.json()["id"]
        await client.post(f"/api/groups/{gid}/members", headers=h, json={"user_id": uid})
        await _policy(client, h, {"subject_type": "group", "subject_id": gid, "environment_id": env_id, "path_prefix": "/",
                                  "actions": ["list", "read"], "effect": "allow", "expires_at": t1.isoformat()})
    box = (await client.post("/api/machines", headers=lead, json={"name": "box", "description": ""})).json()
    await client.post(f"/api/machines/{box['id']}/attach", headers=lead, json={"environment_id": env_id})
    (p,) = await _machine_policies(client, box["id"])
    assert abs(p.expires_at.replace(tzinfo=timezone.utc) - t2) < timedelta(seconds=2), p.expires_at


async def test_password_reset_with_deny_that_expires(client: httpx.AsyncClient, owner_headers, env_id):
    """Запрет актора на /private кончается - ложного отказа нет. Запрет цели
    кончается, а у актора бессрочный - отказ (цель позже получит /private)."""
    h = owner_headers
    later = (NOW() + timedelta(days=1)).isoformat()
    lid = await _user(client, h, "lead", "maintainer")
    await _pol(client, h, lid, env_id, "/", ["list", "read"])
    await _policy(client, h, {"subject_type": "user", "subject_id": lid, "environment_id": env_id, "path_prefix": "/private",
                              "actions": ["list", "read"], "effect": "deny", "expires_at": later})
    lead = await login(client, "lead", PASS)
    dev = await _user(client, h, "dev", "developer")
    await _pol(client, h, dev, env_id, "/", ["list", "read"])
    await _pol(client, h, dev, env_id, "/private", ["list", "read"], allow=False)
    res = await client.post(f"/api/users/{dev}/password", headers=lead, json={"new_password": "lead-knows-it-2026"})
    assert res.status_code == 204, res.text
    # Цель с временным запретом, актор с бессрочным: отказ.
    lid2 = await _user(client, h, "lead2", "maintainer")
    await _pol(client, h, lid2, env_id, "/", ["list", "read"])
    await _pol(client, h, lid2, env_id, "/private", ["list", "read"], allow=False)
    lead2 = await login(client, "lead2", PASS)
    dev2 = await _user(client, h, "dev2", "developer")
    await _pol(client, h, dev2, env_id, "/", ["list", "read"])
    await _policy(client, h, {"subject_type": "user", "subject_id": dev2, "environment_id": env_id, "path_prefix": "/private",
                              "actions": ["list", "read"], "effect": "deny", "expires_at": later})
    res = await client.post(f"/api/users/{dev2}/password", headers=lead2, json={"new_password": "lead-knows-it-2026"})
    assert res.status_code == 403, res.text
    # Цель с правом, которое кончается раньше, чем у актора: не отказ.
    lid3 = await _user(client, h, "lead3", "maintainer")
    await _policy(client, h, {"subject_type": "user", "subject_id": lid3, "environment_id": env_id, "path_prefix": "/",
                              "actions": ["list", "read"], "effect": "allow", "expires_at": (NOW() + timedelta(days=5)).isoformat()})
    lead3 = await login(client, "lead3", PASS)
    dev3 = await _user(client, h, "dev3", "developer")
    await _policy(client, h, {"subject_type": "user", "subject_id": dev3, "environment_id": env_id, "path_prefix": "/",
                              "actions": ["list", "read"], "effect": "allow", "expires_at": later})
    res = await client.post(f"/api/users/{dev3}/password", headers=lead3, json={"new_password": "lead-knows-it-2026"})
    assert res.status_code == 204, res.text


async def test_until_exact_moment_boundary(client: httpx.AsyncClient, owner_headers, env_id):
    """Право машины кончается ровно тогда же, когда у ответственного: в
    _require_reach нет ложного отказа (оба мертвы в момент T)."""
    h = owner_headers
    _uid, lead = await _lead(client, h, env_id, (NOW() + timedelta(days=1)).isoformat())
    box = (await client.post("/api/machines", headers=lead, json={"name": "box", "description": ""})).json()
    await client.post(f"/api/machines/{box['id']}/attach", headers=lead, json={"environment_id": env_id})
    res = await client.post(f"/api/machines/{box['id']}/secret", headers=lead)
    assert res.status_code == 200, res.text


# --- 3. чтение пачкой ------------------------------------------------------------


async def _break_version(client, env, name, path="/", *, generation=None, ciphertext=None):
    async with _app(client).state.session_factory() as session:
        secret = await session.scalar(select(Secret).where(Secret.environment_id == env, Secret.name == name, Secret.path == path))
        values = {}
        if generation is not None:
            values["env_key_generation"] = generation
        if ciphertext is not None:
            values["ciphertext"] = ciphertext
        await session.execute(update(SecretVersion).where(SecretVersion.secret_id == secret.id).values(**values))
        await session.commit()


@pytest.mark.parametrize("kind", ["lost_key", "tampered"])
async def test_broken_key_in_a_denied_folder(client: httpx.AsyncClient, owner_headers, env_id, kind):
    """Ключ в закрытой для машины (и человека) папке не открывается.
    Раньше его не трогали вовсе; теперь values_of открывает все окружение."""
    h = owner_headers
    await _put(client, h, env_id, "A", "1")
    await _put(client, h, env_id, "B", "2", path="/private")
    if kind == "lost_key":
        await _break_version(client, env_id, "B", "/private", generation=77)
    else:
        await _break_version(client, env_id, "B", "/private", ciphertext="QUFBQUFBQUFBQUFBQUFBQUFBQUE=")
    m = await _machine(client, h, env_id)
    await _policy(client, h, {"subject_type": "machine", "subject_id": m["id"], "environment_id": env_id,
                              "path_prefix": "/private", "actions": ["read", "list"], "effect": "deny"})
    agent = await _bearer(client, m)
    out = {}
    for route in ("secrets", "env"):
        res = await run_safely(client.get(f"/api/v1/machine/{route}", headers=agent, params={"project": "billing", "env": "prod"}))
        out[route] = getattr(res, "status_code", repr(res))
        _ = (kind, route, out[route], getattr(res, "text", "")[:160])
    dev = await _user(client, h, "dev", "developer")
    await _pol(client, h, dev, env_id, "/", ["list", "read"])
    await _pol(client, h, dev, env_id, "/private", ["list", "read"], allow=False)
    dh = await login(client, "dev", PASS)
    res = await run_safely(client.get(f"/api/environments/{env_id}/lint", headers=dh))
    out["lint"] = getattr(res, "status_code", repr(res))
    _ = (kind, "lint", out["lint"], getattr(res, "text", "")[:160])
    assert out == {"secrets": 200, "env": 200, "lint": 200}, out


async def test_legacy_name_lost_key_breaks_env_file(client: httpx.AsyncClient, owner_headers, env_id):
    """Имя не по нынешним правилам машине в файл не идет, но values_of его
    открывает: потерянный ключ у него роняет /env целиком."""
    h = owner_headers
    await _put(client, h, env_id, "A", "1")
    async with _app(client).state.session_factory() as session:
        from app.sealbox import SealBox  # noqa: F401
        box = _app(client).state.sealbox
        await secrets_store.set_value(session, box, env_id=env_id, path="/", name="smtp/host", value="x",
                                      author="t", legacy_name=True)
        await session.commit()
    await _break_version(client, env_id, "smtp/host", "/", generation=77)
    agent = await _bearer(client, await _machine(client, h, env_id))
    res = await run_safely(client.get("/api/v1/machine/env", headers=agent, params={"project": "billing", "env": "prod"}))
    _ = ("env file:", getattr(res, "status_code", res), getattr(res, "text", "")[:160])
    assert getattr(res, "status_code", None) == 200


async def test_inherits_between_list_and_values(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Переопределение сняли между списком ключей и чтением версий в values_of:
    у текущей версии inherits и пустой шифротекст."""
    h = owner_headers
    project_id = (await client.get(f"/api/environments/{env_id}", headers=h)).json().get("project_id")
    if project_id is None:
        project_id = (await client.get("/api/projects", headers=h)).json()[0]["id"]
    child = await client.post(f"/api/projects/{project_id}/environments", headers=h, json={"name": "stage", "parent_id": env_id})
    assert child.status_code == 201, child.text
    child = child.json()["id"]
    await _put(client, h, env_id, "X", "parent")
    await _put(client, h, child, "X", "child")
    agent = await _bearer(client, await _machine(client, h, child))

    real = secrets_store.effective_list
    state = {"n": 0, "reached": asyncio.Event(), "release": asyncio.Event()}

    async def wrapped(*args, **kwargs):
        out = await real(*args, **kwargs)
        task = asyncio.current_task()
        if task is not None and task.get_name() == "agent":
            state["n"] += 1
            if state["n"] == 2:  # вызов внутри values_of
                state["reached"].set()
                await state["release"].wait()
        return out

    monkeypatch.setattr(secrets_store, "effective_list", wrapped)
    task = asyncio.create_task(run_safely(client.get("/api/v1/machine/secrets", headers=agent,
                                                     params={"project": "billing", "env": "stage"})), name="agent")
    await asyncio.wait_for(state["reached"].wait(), 5)
    res = await client.post(f"/api/environments/{child}/secret/inherit", headers=h, json={"name": "X", "path": "/"})
    assert res.status_code == 200, res.text
    state["release"].set()
    res = await task
    _ = ("agent:", getattr(res, "status_code", repr(res)), getattr(res, "text", "")[:200])
    assert getattr(res, "status_code", None) == 200


async def test_project_export_matches_per_env(client: httpx.AsyncClient, owner_headers, env_id):
    """Выгрузка проекта с общим memo совпадает с поштучной выгрузкой окружений;
    счетчики списка окружений - с поштучным effective_list."""
    h = owner_headers
    projects = (await client.get("/api/projects", headers=h)).json()
    pid = [p for p in projects if p["slug"] == "billing"][0]["id"]
    envs = [env_id]
    for name in ("stage", "dev"):
        r = await client.post(f"/api/projects/{pid}/environments", headers=h, json={"name": name, "parent_id": env_id})
        assert r.status_code == 201, r.text
        envs.append(r.json()["id"])
    for i in range(5):
        await _put(client, h, env_id, f"K{i}", f"p{i}")
    await _put(client, h, env_id, "DB", "pdb", path="/db")
    await _put(client, h, envs[1], "K1", "s1")
    await _put(client, h, envs[2], "K2", "d2")
    # удаление в наследнике прячет родительский ключ
    await _put(client, h, envs[1], "K3", "s3")
    assert (await client.delete(f"/api/environments/{envs[1]}/secret", headers=h, params={"name": "K3"})).status_code in (200, 204)
    # inherits: снять переопределение
    await client.post(f"/api/environments/{envs[2]}/secret/inherit", headers=h, json={"name": "K2", "path": "/"})
    # одинаковое значение в разных окружениях
    await _put(client, h, envs[2], "K4", "p4")
    whole = (await client.get(f"/api/projects/{pid}/export", headers=h)).json()["text"]
    parts = []
    for e in envs:
        name = {env_id: "prod", envs[1]: "stage", envs[2]: "dev"}[e]
        text = (await client.get(f"/api/environments/{e}/export", headers=h)).json()["text"]
        parts.append(f"# --- billing/{name} ---\n{text}")
    assert whole == "\n".join(parts), (whole, parts)
    listed = {e["id"]: e["secret_count"] for e in (await client.get(f"/api/projects/{pid}/environments", headers=h)).json()}
    async with _app(client).state.session_factory() as session:
        for e in envs:
            assert listed[e] == len(await secrets_store.effective_list(session, e)), (e, listed)


# --- 2. lock_env и транзакции ----------------------------------------------------


async def test_lock_env_after_rollback_and_in_savepoint(client: httpx.AsyncClient, owner_headers, env_id):
    from sqlalchemy import event

    log: list[str] = []
    engine = _app(client).state.engine

    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, params, context, executemany):
        if "FROM environments" in statement:
            log.append(statement)

    async with _app(client).state.session_factory() as session:
        await secrets_store.lock_env(session, env_id)
        n1 = len(log)
        await secrets_store.lock_env(session, env_id)
        assert len(log) == n1  # пропуск в той же транзакции
        await session.rollback()
        await secrets_store.lock_env(session, env_id)
        assert len(log) == n1 + 1, "после rollback блокировка не взята заново"
        await session.commit()
        await secrets_store.lock_env(session, env_id)
        assert len(log) == n1 + 2, "после commit блокировка не взята заново"
        await session.commit()
        # Точка сохранения: блокировка, взятая в ней и отпущенная откатом к ней
        # (на Postgres строчная блокировка подтранзакции снимается), считается
        # удержанной.
        nested = await session.begin_nested()
        await secrets_store.lock_env(session, env_id)
        await nested.rollback()
        before = len(log)
        await secrets_store.lock_env(session, env_id)
        _ = ("после отката точки сохранения перечитано:", len(log) - before)


# --- 5. оповещения ---------------------------------------------------------------


async def test_notify_later_channel_combinations(client: httpx.AsyncClient, owner_headers, monkeypatch):
    from app import alerts

    codes = {"tg": 200, "hook": 200}
    original = httpx.AsyncClient

    def fake(*args, **kwargs):
        def handler(request):
            return httpx.Response(codes["tg"] if "/bot" in str(request.url) else codes["hook"], json={})

        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(alerts.httpx, "AsyncClient", fake)
    factory = _app(client).state.session_factory
    cfgs = {
        "none": {},
        "tg": {"telegram_token": "123456789:abc", "telegram_chat": "1"},
        "both": {"telegram_token": "123456789:abc", "telegram_chat": "1", "webhook": "https://h.example/x"},
        "tg_no_chat_plus_hook": {"telegram_token": "123456789:abc", "webhook": "https://h.example/x"},
    }
    results = {}
    for name, cfg in cfgs.items():
        async def get_config(session, settings=None, cfg=cfg):
            return cfg

        monkeypatch.setattr(alerts, "get_config", get_config)
        for tg, hook in ((200, 200), (502, 200), (200, 502), (502, 502)):
            codes.update(tg=tg, hook=hook)
            results[(name, tg, hook)] = await alerts.notify_later(factory, "t")
    for k, v in results.items():
        _ = (k, v)
    assert results[("none", 502, 502)] is True
    assert results[("both", 502, 200)] is True and results[("both", 502, 502)] is False
    assert results[("tg", 502, 200)] is False
    assert results[("tg_no_chat_plus_hook", 200, 502)] is False

    async def boom(session, settings=None):
        raise RuntimeError("db down")

    monkeypatch.setattr(alerts, "get_config", boom)
    assert await alerts.notify_later(factory, "t") is False


async def test_fleet_silent_retry_until_delivered(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    from app import fleet_watch, settings_store

    h = owner_headers
    m = await _machine(client, h, env_id)
    factory = _app(client).state.session_factory
    async with factory() as session:
        row = await session.get(MachineIdentity, m["id"])
        row.last_seen_at = NOW() - timedelta(days=3)
        await session.commit()
    sent: list[str] = []
    ok = {"v": False}

    async def fake_notify(session_factory, text):
        sent.append(text)
        return ok["v"]

    monkeypatch.setattr(fleet_watch.alerts, "notify_later", fake_notify)
    assert await fleet_watch.sweep_silent(factory) == 0
    assert await fleet_watch.sweep_silent(factory) == 0
    ok["v"] = True
    assert await fleet_watch.sweep_silent(factory) == 1
    assert await fleet_watch.sweep_silent(factory) == 0
    assert len(sent) == 3, sent
    async with factory() as session:
        assert (await settings_store.get(session, fleet_watch.SILENT_KEY, "")) == str(m["id"])


async def test_lint_marks_with_env_deleted_during_delivery(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Окружение удалили, пока шло сообщение: вставка отметок упирается во
    внешний ключ и роняет все отметки разом."""
    from app import lint_watch

    h = owner_headers
    projects = (await client.get("/api/projects", headers=h)).json()
    pid = [p for p in projects if p["slug"] == "billing"][0]["id"]
    other = (await client.post("/api/projects", headers=h, json={"slug": "tmp"})).json()["id"]
    tenv = (await client.post(f"/api/projects/{other}/environments", headers=h, json={"name": "prod"})).json()["id"]
    await _put(client, h, env_id, "PASSWORD", "changeme")
    await _put(client, h, tenv, "PASSWORD", "changeme")
    factory = _app(client).state.session_factory
    box = _app(client).state.sealbox
    sent: list[str] = []

    async def fake_notify(session_factory, text):
        sent.append(text)
        if len(sent) == 1:
            r = await client.delete(f"/api/projects/{other}", headers=h, params={"confirm": "tmp"})
            assert r.status_code in (200, 204), r.text
        return True

    monkeypatch.setattr(lint_watch.alerts, "notify_later", fake_notify)
    first = await run_safely(lint_watch.sweep(factory, box))
    second = await run_safely(lint_watch.sweep(factory, box))
    _ = ("first:", repr(first), "second:", repr(second), "sent:", len(sent))
    assert len(sent) == 1, "оповещение о billing/prod ушло повторно"


# --- 6. даты ---------------------------------------------------------------------


async def test_dates_plain_and_end_of_day(client: httpx.AsyncClient, owner_headers, env_id):
    h = owner_headers
    uid = await _user(client, h, "dev", "developer")
    cases = {
        "2027-03-01": "2027-03-01T00:00:00+00:00",
        "2027-03-01T20:59:59.000Z": "2027-03-01T20:59:59+00:00",
        "2027-03-01T23:59:59-05:00": "2027-03-02T04:59:59+00:00",
    }
    for raw, want in cases.items():
        r = await client.post("/api/policies", headers=h, json={"subject_type": "user", "subject_id": uid, "environment_id": env_id,
                                                                "path_prefix": "/", "actions": ["list"], "effect": "allow",
                                                                "expires_at": raw})
        assert r.status_code == 201, r.text
        got = [p["expires_at"] for p in (await client.get("/api/policies", headers=h)).json() if p["id"] == r.json()["id"]][0]
        assert got == want, (raw, got)
    await _put(client, h, env_id, "CERT", "x")
    r = await client.post(f"/api/environments/{env_id}/secret/meta", headers=h, json={"name": "CERT", "path": "/", "note": "", "expires_at": "2027-03-01"})
    assert r.status_code == 200, r.text
    rows = (await client.get(f"/api/environments/{env_id}/secrets", headers=h)).json()
    _ = ("secret expiry:", [x["expires_at"] for x in rows if x["name"] == "CERT"])
    assert [x["expires_at"] for x in rows if x["name"] == "CERT"][0].startswith("2027-03-01")
    for raw in ("2027-03-01Z", "2027-03-01T10:00Z", "9999-12-31", "9999-12-31T23:59:59+00:00", "0001-01-01"):
        r = await client.post(f"/api/environments/{env_id}/secret/meta", headers=h, json={"name": "CERT", "path": "/", "note": "", "expires_at": raw})
        m = await client.post("/api/machines", headers=h, json={"name": f"m{abs(hash(raw)) % 9999}", "description": "", "expires_at": raw})
        _ = (raw, "meta", r.status_code, "machine", m.status_code)
        assert r.status_code in (200, 400) and m.status_code in (201, 400), (raw, r.text, m.text)


async def test_shadowed_duplicate_name_breaks_machine_read(client: httpx.AsyncClient, owner_headers, env_id):
    """Одноименный ключ в / проигрывает /db по one_per_name и машине не идет,
    но values_of его открывает."""
    h = owner_headers
    await _put(client, h, env_id, "DB", "root")
    await _put(client, h, env_id, "DB", "db", path="/db")
    await _break_version(client, env_id, "DB", "/", generation=77)
    agent = await _bearer(client, await _machine(client, h, env_id))
    res = await run_safely(client.get("/api/v1/machine/secrets", headers=agent, params={"project": "billing", "env": "prod"}))
    _ = ("shadowed:", getattr(res, "status_code", res), getattr(res, "text", "")[:160])
    assert getattr(res, "status_code", None) == 200


# --- 4. удаление по ходу запроса -------------------------------------------------


@pytest.mark.parametrize("op", ["import", "restore", "snapshot", "copy_from"])
async def test_ops_on_a_project_deleted_meanwhile(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch, op):
    h = owner_headers
    slug = f"gone-{op.replace('_', '-')}"
    project = (await client.post("/api/projects", headers=h, json={"slug": slug})).json()
    env = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "prod"})).json()["id"]
    await _put(client, h, env, "A", "1")
    base = f"/api/environments/{env}"
    if op == "import":
        request = client.post(f"{base}/import", headers=h, json={"text": "B=2\n", "overwrite": True})
    elif op == "restore":
        snap = (await client.post(f"{base}/snapshots", headers=h, json={"name": "s"})).json()
        await _put(client, h, env, "A", "2")
        request = client.post(f"{base}/snapshots/{snap['id']}/restore", headers=h)
    elif op == "snapshot":
        request = client.post(f"{base}/snapshots", headers=h, json={"name": "s2"})
    else:
        other = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "dev"})).json()["id"]
        await _put(client, h, other, "B", "x")
        request = client.post(f"{base}/copy-from", headers=h, json={"source": "dev", "name": "B", "path": "/"})
    gate = Gate(op)
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated(op, request, gate)
    res = await client.delete(f"/api/projects/{project['id']}", headers=h, params={"confirm": slug})
    assert res.status_code in (200, 204), res.text
    gate.release.set()
    res = await task
    _ = (op, getattr(res, "status_code", repr(res)), getattr(res, "text", "")[:160])
    assert getattr(res, "status_code", None) in (404, 409), (op, res)


async def test_create_env_in_a_project_deleted_after_checks(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    from app.api import projects as projects_api

    h = owner_headers
    project = (await client.post("/api/projects", headers=h, json={"slug": "gone-env"})).json()
    gate = Gate("create")
    gate_async(monkeypatch, projects_api, "_check_parent", gate)
    task = await _gated("create", client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "prod"}), gate)
    res = await client.delete(f"/api/projects/{project['id']}", headers=h, params={"confirm": "gone-env"})
    assert res.status_code in (200, 204), res.text
    gate.release.set()
    res = await task
    _ = ("create env:", getattr(res, "status_code", repr(res)), getattr(res, "text", "")[:160])
    assert getattr(res, "status_code", None) == 404
