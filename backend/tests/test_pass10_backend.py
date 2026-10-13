"""Десятый проход: нагрузка, масштаб и время на живой панели."""

import httpx

from app import secrets_store
from tests.test_pass9_backend import Gate, _bearer, _gated, _machine, gate_async


async def _put(client, h, env, name, value, path="/"):
    res = await client.put(f"/api/environments/{env}/secrets", headers=h, json={"name": name, "value": value, "path": path})
    assert res.status_code == 200, res.text


async def test_reading_a_whole_env_survives_a_key_deleted_meanwhile(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Ключ удалили между списком и чтением значений: агент, /values и
    /export получают окружение без него, а не 404 на все окружение."""
    h = owner_headers
    await _put(client, h, env_id, "A", "1")
    await _put(client, h, env_id, "GONE", "2")
    agent = await _bearer(client, await _machine(client, h, env_id))
    requests = {
        "agent": lambda: client.get("/api/v1/machine/secrets", headers=agent, params={"project": "billing", "env": "prod"}),
        "values": lambda: client.get(f"/api/environments/{env_id}/values", headers=h),
        "export": lambda: client.get(f"/api/environments/{env_id}/export", headers=h),
    }
    for name, make in requests.items():
        await _put(client, h, env_id, "GONE", "2")
        gate = Gate(name)
        gate_async(monkeypatch, secrets_store, "values_of", gate)
        task = await _gated(name, make(), gate)
        res = await client.delete(f"/api/environments/{env_id}/secret", headers=h, params={"name": "GONE"})
        assert res.status_code in (200, 204), res.text
        gate.release.set()
        res = await task
        assert getattr(res, "status_code", res) == 200, (name, getattr(res, "text", res))
        assert "GONE" not in res.text, name


# --- временные права -------------------------------------------------------------


async def _temporary_lead(client, h, env_id, until):
    from tests.conftest import login
    from tests.test_pass8b_backend import PASS, _user

    uid = await _user(client, h, "lead", "maintainer")
    res = await client.post(
        "/api/policies",
        headers=h,
        json={"subject_type": "user", "subject_id": uid, "environment_id": env_id, "path_prefix": "/",
              "actions": ["list", "read"], "effect": "allow", "expires_at": until},
    )
    assert res.status_code == 201, res.text
    return await login(client, "lead", PASS)


async def _machine_policy_expiry(client, machine_id):
    from sqlalchemy import select

    from app.models import Policy

    app = client._transport.app
    async with app.state.session_factory() as session:
        return await session.scalar(
            select(Policy.expires_at).where(Policy.subject_type == "machine", Policy.subject_id == machine_id)
        )


async def test_a_machine_gets_no_longer_than_its_temporary_lead(client: httpx.AsyncClient, owner_headers, env_id):
    """Ответственный с prod до завтра подключает машину: ее право кончается
    вместе с его, а не живет без срока."""
    from datetime import datetime, timedelta, timezone

    h = owner_headers
    until = datetime.now(timezone.utc) + timedelta(days=1)
    lead = await _temporary_lead(client, h, env_id, until.isoformat())
    box = (await client.post("/api/machines", headers=lead, json={"name": "contractor-box", "description": ""})).json()
    res = await client.post(f"/api/machines/{box['id']}/attach", headers=lead, json={"environment_id": env_id})
    assert res.status_code == 200, res.text
    expires = await _machine_policy_expiry(client, box["id"])
    assert expires is not None
    assert abs(expires.replace(tzinfo=timezone.utc) - until) < timedelta(seconds=2)
    # Через токен подключения - так же.
    token = (await client.post("/api/machines/enroll-token", headers=lead, json={"environment_id": env_id})).json()["token"]
    enrolled = await client.post("/api/v1/machine/enroll", json={"token": token, "hostname": "vps-1"})
    assert enrolled.status_code == 200, enrolled.text
    from sqlalchemy import select

    from app.models import MachineIdentity

    app = client._transport.app
    async with app.state.session_factory() as session:
        vps = await session.scalar(select(MachineIdentity.id).where(MachineIdentity.client_id == enrolled.json()["client_id"]))
    assert (await _machine_policy_expiry(client, vps)) is not None


async def test_a_temporary_lead_cannot_reset_a_permanent_password(client: httpx.AsyncClient, owner_headers, env_id):
    """Сброс пароля разработчику с бессрочным правом дал бы временному
    ответственному доступ без срока: отказ."""
    from datetime import datetime, timedelta, timezone

    from tests.test_pass8b_backend import _pol, _user

    h = owner_headers
    lead = await _temporary_lead(client, h, env_id, (datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    dev_id = await _user(client, h, "dev", "developer")
    await _pol(client, h, dev_id, env_id, "/", ["list", "read"])
    res = await client.post(f"/api/users/{dev_id}/password", headers=lead, json={"new_password": "lead-knows-it-2026"})
    assert res.status_code == 403, res.text


# --- оповещения и сроки ---------------------------------------------------------


async def test_a_machine_past_its_date_is_not_reported_as_silent(client: httpx.AsyncClient, owner_headers, env_id):
    from datetime import datetime, timedelta, timezone

    from app import fleet_watch
    from app.config import get_settings
    from app.db import create_engine_and_factory
    from app.models import MachineIdentity

    h = owner_headers
    made = (await client.post("/api/machines", headers=h, json={"name": "contractor-ci", "description": "", "expires_at": "2026-01-01"})).json()
    res = await client.post("/api/policies", headers=h, json={"subject_type": "machine", "subject_id": made["id"], "environment_id": env_id,
                                                             "path_prefix": "/", "actions": ["read"], "effect": "allow"})
    assert res.status_code == 201, res.text
    engine, factory = create_engine_and_factory(get_settings().db_url)
    try:
        async with factory() as session:
            row = await session.get(MachineIdentity, made["id"])
            row.last_seen_at = datetime.now(timezone.utc) - timedelta(days=3)
            await session.commit()
        assert await fleet_watch.sweep_silent(factory) == 0
    finally:
        await engine.dispose()


async def test_a_reminder_waits_for_a_working_channel(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Канал лежал в момент обхода: напоминание приходит, когда он поднялся,
    а не теряется навсегда."""
    from datetime import datetime, timedelta, timezone

    from app import alerts, lint_watch
    from app.config import get_settings
    from app.db import create_engine_and_factory

    h = owner_headers
    await _put(client, h, env_id, "CERT_KEY", "x")
    soon = (datetime.now(timezone.utc) + timedelta(days=3)).date().isoformat()
    res = await client.post(f"/api/environments/{env_id}/secret/meta", headers=h, json={"name": "CERT_KEY", "path": "/", "note": "", "expires_at": soon})
    assert res.status_code == 200, res.text

    async def cfg(session, settings=None):
        return {"webhook": "https://hooks.example/x"}

    monkeypatch.setattr(alerts, "get_config", cfg)
    delivered: list[str] = []
    status = {"code": 502}
    original = httpx.AsyncClient

    def fake(*args, **kwargs):
        def handler(request):
            if status["code"] == 200:
                delivered.append(request.content.decode())
            return httpx.Response(status["code"])

        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(alerts.httpx, "AsyncClient", fake)
    engine, factory = create_engine_and_factory(get_settings().db_url)
    try:
        await lint_watch.sweep_expiry(factory)
        status["code"] = 200
        await lint_watch.sweep_expiry(factory)
        await lint_watch.sweep_expiry(factory)
    finally:
        await engine.dispose()
    assert len([body for body in delivered if "CERT_KEY" in body]) == 1


async def test_dates_with_an_offset_are_stored_in_utc(client: httpx.AsyncClient, owner_headers, env_id):
    from tests.test_pass8b_backend import _user

    h = owner_headers
    uid = await _user(client, h, "dev", "developer")
    made = await client.post("/api/policies", headers=h, json={"subject_type": "user", "subject_id": uid, "environment_id": env_id,
                                                              "path_prefix": "/", "actions": ["list"], "effect": "allow",
                                                              "expires_at": "2030-01-01T00:00:00+03:00"})
    assert made.status_code == 201, made.text
    stored = [p["expires_at"] for p in (await client.get("/api/policies", headers=h)).json() if p["subject_name"] == "dev"][0]
    assert stored == "2029-12-31T21:00:00+00:00", stored
    await _put(client, h, env_id, "CERT_KEY", "x")
    for raw in ("9999-12-31T23:00:00-03:00", "0001-01-01T00:00:00+03:00"):
        res = await client.post(f"/api/environments/{env_id}/secret/meta", headers=h, json={"name": "CERT_KEY", "path": "/", "note": "", "expires_at": raw})
        assert res.status_code == 400, (raw, res.text)
        res = await client.post("/api/machines", headers=h, json={"name": "edge", "description": "", "expires_at": raw})
        assert res.status_code == 400, (raw, res.text)


async def test_a_write_into_a_project_deleted_meanwhile_is_409(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    """Проект удалили, пока запись или смена ключа ждали блокировку: 409
    "окружение удалили", а не 500 на внешнем ключе и не совет восстанавливать
    базу из бэкапа."""
    h = owner_headers
    for name in ("write", "rotate"):
        slug = f"gone-{name}"
        project = (await client.post("/api/projects", headers=h, json={"slug": slug})).json()
        env = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "prod"})).json()["id"]
        await _put(client, h, env, "A", "1")
        if name == "write":
            request = client.put(f"/api/environments/{env}/secrets", headers=h, json={"name": "A", "value": "2"})
        else:
            request = client.post(f"/api/environments/{env}/rotate-key", headers=h)
        gate = Gate(name)
        gate_async(monkeypatch, secrets_store, "lock_env", gate)
        task = await _gated(name, request, gate)
        res = await client.delete(f"/api/projects/{project['id']}", headers=h, params={"confirm": slug})
        assert res.status_code in (200, 204), res.text
        gate.release.set()
        res = await task
        assert getattr(res, "status_code", res) == 409, (name, getattr(res, "text", res))


# --- объемы ---------------------------------------------------------------------


def _statements(client):
    from sqlalchemy import event

    log: list[str] = []
    app = client._transport.app

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, params, context, executemany):
        log.append(" ".join(statement.split()))

    return log


async def test_a_whole_env_is_read_in_a_batch(client: httpx.AsyncClient, owner_headers, env_id):
    """Агент читает окружение пачкой: число запросов к базе не растет с
    числом ключей (по ключу за раз 5000 ключей отдавались 5-6 с)."""
    h = owner_headers
    agent = await _bearer(client, await _machine(client, h, env_id))
    for i in range(120):
        await _put(client, h, env_id, f"K{i:03d}", f"v{i}")
    log = _statements(client)
    res = await client.get("/api/v1/machine/secrets", headers=agent, params={"project": "billing", "env": "prod"})
    assert res.status_code == 200 and len(res.json()["values"]) == 120
    assert len(log) < 60, len(log)


async def test_restoring_a_snapshot_locks_once(client: httpx.AsyncClient, owner_headers, env_id):
    """Восстановление не перечитывает все ключи на каждом шаге: на 2800 ключах
    это было 131 с и 504 через nginx."""
    h = owner_headers
    base = f"/api/environments/{env_id}"
    for i in range(60):
        await _put(client, h, env_id, f"K{i:03d}", "a")
    snap = (await client.post(f"{base}/snapshots", headers=h, json={"name": "s"})).json()
    for i in range(60):
        await _put(client, h, env_id, f"K{i:03d}", "b")
    log = _statements(client)
    res = await client.post(f"{base}/snapshots/{snap['id']}/restore", headers=h)
    assert res.status_code == 200, res.text
    refreshes = [s for s in log if s.startswith("SELECT") and "FROM secrets WHERE secrets.id IN" in s]
    assert len(refreshes) <= 2, len(refreshes)


async def test_reattach_extends_an_expired_machine_right(client: httpx.AsyncClient, owner_headers, env_id):
    """Право машины кончилось вместе с доступом временного ответственного:
    повторное подключение владельцем продлевает его, а не отвечает "доступ уже
    был", пока агент получает 403. Истекшее право в списке серверов не
    числится."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from app.models import Policy

    h = owner_headers
    box = (await client.post("/api/machines", headers=h, json={"name": "box", "description": ""})).json()
    res = await client.post(f"/api/machines/{box['id']}/attach", headers=h, json={"environment_id": env_id})
    assert res.status_code == 200 and res.json()["expires_at"] == ""
    app = client._transport.app
    async with app.state.session_factory() as session:
        await session.execute(
            update(Policy)
            .where(Policy.subject_type == "machine", Policy.subject_id == box["id"])
            .values(expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
        )
        await session.commit()
    listed = next(m for m in (await client.get("/api/machines", headers=h)).json() if m["id"] == box["id"])
    assert listed["environments"] == []
    res = await client.post(f"/api/machines/{box['id']}/attach", headers=h, json={"environment_id": env_id})
    assert res.status_code == 200 and res.json()["granted"] is True and res.json()["expires_at"] == ""
    agent = await _bearer(client, box)
    pulled = await client.get("/api/v1/machine/secrets", headers=agent, params={"project": "billing", "env": "prod"})
    assert pulled.status_code == 200, pulled.text
