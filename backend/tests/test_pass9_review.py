"""Ревью девятого прохода: дыры в самих исправлениях."""

import asyncio
import base64

import httpx
from sqlalchemy import event, func, select, text

from app import secrets_store
from app.main import LOST_ACTIVE_KEY
from app.models import AuditLog, LoginFailure
from tests.conftest import OWNER_PASSWORD, login
from tests.test_pass8b_backend import PASS, _pol, _user
from tests.test_pass9_backend import Gate, _gated, _machine, gate_async, run_safely


async def _put(client, h, env, name, value, path="/"):
    res = await client.put(f"/api/environments/{env}/secrets", headers=h, json={"name": name, "value": value, "path": path})
    assert res.status_code == 200, res.text


async def _project(client, h, slug="shop", envs=("dev", "prod")):
    res = await client.post("/api/projects", headers=h, json={"slug": slug, "environments": list(envs)})
    assert res.status_code == 201, res.text
    pid = res.json()["id"]
    return pid, {e["name"]: e["id"] for e in (await client.get(f"/api/projects/{pid}/environments", headers=h)).json()}


async def _count(client, model, *where):
    app = client._transport.app
    async with app.state.session_factory() as session:
        return await session.scalar(select(func.count()).select_from(model).where(*where))


async def test_rename_everywhere_refuses_a_key_moved_meanwhile(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    """Пока переименование "везде" ждало блокировки, ключ унесли в закрытую
    папку: переименование отказывает, а не выносит значение оттуда."""
    h = owner_headers
    _pid, envs = await _project(client, h)
    uid = await _user(client, h, "dev", "developer")
    for env in envs.values():
        await _pol(client, h, uid, env, "/", ["list", "read", "write"])
        await _pol(client, h, uid, env, "/private", ["list", "read"], allow=False)
    dev = await login(client, "dev", PASS)
    prod = envs["prod"]
    await _put(client, h, prod, "X", "public-value")
    gate = Gate("dev-rename")
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated(
        "dev-rename",
        client.post(f"/api/environments/{prod}/secret/rename", headers=dev,
                    json={"name": "X", "path": "/", "new_name": "Y", "new_path": "/", "everywhere": True}),
        gate,
    )
    res = await client.post(f"/api/environments/{prod}/secret/rename", headers=h,
                            json={"name": "X", "path": "/", "new_name": "X", "new_path": "/private"})
    assert res.status_code == 200, res.text
    await _put(client, h, prod, "X", "top-secret-after-move", path="/private")
    gate.release.set()
    assert getattr(await task, "status_code", None) == 409
    assert (await client.get(f"/api/environments/{prod}/secret", headers=dev, params={"name": "Y"})).status_code == 404
    owner_view = await client.get(f"/api/environments/{prod}/secret", headers=h, params={"name": "X", "path": "/private"})
    assert owner_view.json()["value"] == "top-secret-after-move"


async def test_env_patch_locks_before_touching_the_row(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    h = owner_headers
    _pid, envs = await _project(client, h, slug="ord", envs=("a", "b", "c"))
    app = client._transport.app
    log: list[str] = []

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, params, context, executemany):
        log.append(" ".join(statement.split()))

    real = secrets_store.lock_env

    async def marked(session, env_id):
        log.append("<lock>")
        await real(session, env_id)

    monkeypatch.setattr(secrets_store, "lock_env", marked)
    res = await client.patch(f"/api/environments/{envs['c']}", headers=h, json={"title": "C!", "parent_id": envs["a"]})
    assert res.status_code == 200, res.text
    update = next(i for i, s in enumerate(log) if s.startswith("UPDATE environments SET title"))
    assert log.index("<lock>") < update


async def test_old_names_move_inside_the_panel(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    """Копия окружения и раскладка не падают целиком из-за ключа со старым
    именем: оно уже есть в панели, и агент его все равно пропустит."""
    h = owner_headers
    pid, envs = await _project(client, h, slug="old")
    real = secrets_store._NAME_OK
    monkeypatch.setattr(secrets_store, "_NAME_OK", __import__("re").compile(r".+"))
    await _put(client, h, envs["prod"], "smtp/host", "mail.example")
    monkeypatch.setattr(secrets_store, "_NAME_OK", real)
    await _put(client, h, envs["prod"], "GOOD", "1")
    res = await client.post(f"/api/projects/{pid}/environments", headers=h, json={"name": "stage", "copy_from": envs["prod"]})
    assert res.status_code == 201, res.text
    names = {r["name"] for r in (await client.get(f"/api/environments/{res.json()['id']}/secrets", headers=h)).json()}
    assert names == {"smtp/host", "GOOD"}
    res = await client.post(f"/api/environments/{envs['prod']}/spread", headers=h,
                            json={"path": "/", "name": "smtp/host", "targets": [envs["dev"]]})
    assert res.status_code == 200, res.text
    # Новое такое имя по-прежнему не заводится.
    res = await client.put(f"/api/environments/{envs['dev']}/secrets", headers=h, json={"name": "a:b", "value": "v"})
    assert res.status_code == 400


async def test_refusals_of_a_known_machine_do_not_flood_the_journal(client: httpx.AsyncClient, owner_headers, env_id):
    """ESO с выключенной машиной опрашивает часто: строка журнала раз в час и
    401 с настоящей причиной, а не 429."""
    h = owner_headers
    machine = await _machine(client, h, env_id, name="eso")
    assert (await client.patch(f"/api/machines/{machine['id']}", headers=h, json={"disabled": True})).status_code == 200
    pair = base64.b64encode(f"{machine['client_id']}:{machine['client_secret']}".encode()).decode()
    codes = []
    for _ in range(40):
        res = await client.get("/api/v1/machine/secrets", headers={"Authorization": "Basic " + pair}, params={"project": "billing", "env": "prod"})
        codes.append(res.status_code)
    assert set(codes) == {401}
    assert await _count(client, AuditLog, AuditLog.action == "machine_denied") == 1


async def test_a_burst_of_right_passwords_leaves_no_failures(client: httpx.AsyncClient, owner_headers):
    async def one():
        return await run_safely(client.post("/api/auth/login", json={"username": "owner", "password": OWNER_PASSWORD}))

    await asyncio.gather(*[one() for _ in range(20)])
    assert await _count(client, LoginFailure, LoginFailure.key.notlike("user:%")) == 0


async def test_enroll_token_of_a_demoted_creator_is_dead(client: httpx.AsyncClient, owner_headers, env_id):
    h = owner_headers
    lead_id = await _user(client, h, "lead", "maintainer")
    await _pol(client, h, lead_id, env_id, "/", ["list", "read"])
    lead = await login(client, "lead", PASS)
    token = (await client.post("/api/machines/enroll-token", headers=lead, json={"environment_id": env_id})).json()["token"]
    assert (await client.patch(f"/api/users/{lead_id}", headers=h, json={"role": "developer"})).status_code == 200
    res = await client.post("/api/v1/machine/enroll", json={"token": token, "hostname": "web-1"})
    assert res.status_code == 401, res.text


async def test_missing_active_key_says_so(client: httpx.AsyncClient, owner_headers, env_id):
    app = client._transport.app
    async with app.state.session_factory() as session:
        await session.execute(text("DELETE FROM env_keys WHERE environment_id = :env"), {"env": env_id})
        await session.commit()
    res = await client.put(f"/api/environments/{env_id}/secrets", headers=owner_headers, json={"name": "K", "value": "v"})
    assert res.status_code == 500 and res.json()["detail"] == LOST_ACTIVE_KEY
