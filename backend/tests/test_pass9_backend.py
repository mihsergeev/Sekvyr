"""Девятый проход: гонки, вход и учетные данные машин.

Гонки воспроизводятся порядком, который на Postgres дает блокировка: запрос
успел прочитать и ждет, другой в это время коммитит. На SQLite блокировок строк
нет, поэтому ожидание заменяют ворота (Gate): первый вызов функции в задаче с
нужным именем стоит, пока тест его не отпустит.
"""

import asyncio
import base64
import time

import httpx
import pytest
from sqlalchemy import event, select

from app import audit, envkeys, ratelimit, secrets_store, totp
from app.api import auth as auth_api
from app.api import projects as projects_api
from app.models import AuditLog
from tests.conftest import PG, login
from tests.test_pass8b_backend import PASS, _pol, _user


class Gate:
    def __init__(self, task_name: str):
        self.task_name = task_name
        self.reached = asyncio.Event()
        self.release = asyncio.Event()
        self.used = False

    async def maybe_wait(self):
        task = asyncio.current_task()
        if not self.used and task is not None and task.get_name() == self.task_name:
            self.used = True
            self.reached.set()
            await self.release.wait()


def gate_async(monkeypatch, module, attr, gate: Gate):
    orig = getattr(module, attr)

    async def wrapper(*args, **kwargs):
        await gate.maybe_wait()
        return await orig(*args, **kwargs)

    monkeypatch.setattr(module, attr, wrapper)


async def run_safely(coro):
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001
        return exc


async def _gated(name, coro, gate):
    task = asyncio.create_task(run_safely(coro), name=name)
    await asyncio.wait_for(gate.reached.wait(), 5)
    return task


async def _put(client, h, env, name, value, path="/"):
    res = await client.put(f"/api/environments/{env}/secrets", headers=h, json={"name": name, "value": value, "path": path})
    assert res.status_code == 200, res.text


async def _read(client, h, env, name, path="/"):
    return await client.get(f"/api/environments/{env}/secret", headers=h, params={"name": name, "path": path})


async def _machine(client, h, env, name="node", actions=("read", "list")):
    machine = (await client.post("/api/machines", headers=h, json={"name": name, "description": ""})).json()
    if env is not None:
        res = await client.post(
            "/api/policies",
            headers=h,
            json={"subject_type": "machine", "subject_id": machine["id"], "environment_id": env,
                  "path_prefix": "/", "actions": list(actions), "effect": "allow"},
        )
        assert res.status_code == 201, res.text
    return machine


async def _bearer(client, machine):
    res = await client.post("/api/v1/machine/token", json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]})
    assert res.status_code == 200, res.text
    return {"Authorization": "Bearer " + res.json()["access_token"]}


def _wrap_body() -> dict:
    return {
        "salt": base64.b64encode(b"s" * 16).decode(),
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "wrapped_key": base64.b64encode(b"w" * 48).decode(),
        "verifier_nonce": base64.b64encode(b"v" * 12).decode(),
        "verifier": base64.b64encode(b"m" * 32).decode(),
    }


# --- гонки над ключом -----------------------------------------------------------


async def test_rollback_vs_rename_keeps_the_key_readable(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Откат ждал блокировку, ключ переименовали: откат отказывает, а не пишет
    версию под старым именем (после нее окружение не отдавалось целиком)."""
    h, base = owner_headers, f"/api/environments/{env_id}"
    await _put(client, h, env_id, "OTHER", "x")
    await _put(client, h, env_id, "X", "v1")
    await _put(client, h, env_id, "X", "v2")
    agent = await _bearer(client, await _machine(client, h, env_id))
    gate = Gate("rollback")
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated("rollback", client.post(f"{base}/secret/rollback", headers=h, json={"name": "X", "version": 1}), gate)
    assert (await client.post(f"{base}/secret/rename", headers=h, json={"name": "X", "new_name": "Y"})).status_code == 200
    gate.release.set()
    res = await task
    assert res.status_code in (400, 409), res
    read = await _read(client, h, env_id, "Y")
    assert read.status_code == 200 and read.json()["value"] == "v2"
    pulled = await client.get("/api/v1/machine/secrets", headers=agent, params={"project": "billing", "env": "prod"})
    assert pulled.status_code == 200, pulled.text


async def test_rollback_after_a_concurrent_delete_brings_the_key_back(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    h, base = owner_headers, f"/api/environments/{env_id}"
    await _put(client, h, env_id, "X", "a")
    await _put(client, h, env_id, "X", "b")
    gate = Gate("rollback")
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated("rollback", client.post(f"{base}/secret/rollback", headers=h, json={"name": "X", "version": 1}), gate)
    assert (await client.delete(f"{base}/secret", headers=h, params={"name": "X"})).status_code in (200, 204)
    gate.release.set()
    assert (await task).status_code == 200
    read = await _read(client, h, env_id, "X")
    assert read.status_code == 200 and read.json()["value"] == "a"
    # Ключ живой и для удаления: раньше строка оставалась с флагом "удален".
    assert (await client.delete(f"{base}/secret", headers=h, params={"name": "X"})).status_code in (200, 204)
    assert (await _read(client, h, env_id, "X")).status_code == 404


async def test_rename_keeps_a_concurrent_write(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    h, base = owner_headers, f"/api/environments/{env_id}"
    await _put(client, h, env_id, "X", "old")
    gate = Gate("rename")
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated("rename", client.post(f"{base}/secret/rename", headers=h, json={"name": "X", "new_name": "Y"}), gate)
    await _put(client, h, env_id, "X", "hotfix")
    gate.release.set()
    assert (await task).status_code == 200
    assert (await _read(client, h, env_id, "Y")).json()["value"] == "hotfix"


async def test_import_without_overwrite_keeps_a_concurrent_key(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    h, base = owner_headers, f"/api/environments/{env_id}"
    gate = Gate("import")
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated(
        "import", client.post(f"{base}/import", headers=h, json={"text": "A=from-file\nB=2\n", "overwrite": False}), gate
    )
    await _put(client, h, env_id, "A", "manual")
    gate.release.set()
    assert (await task).status_code == 200
    assert (await _read(client, h, env_id, "A")).json()["value"] == "manual"
    assert (await _read(client, h, env_id, "B")).json()["value"] == "2"


async def test_restore_of_a_deleted_snapshot_leaves_the_env_alone(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Снимок удалили, пока восстановление ждало: раньше это стирало окружение."""
    h, base = owner_headers, f"/api/environments/{env_id}"
    for name in ("DB_URL", "API_KEY", "TOKEN"):
        await _put(client, h, env_id, name, "v1")
    snap = (await client.post(f"{base}/snapshots", headers=h, json={"name": "before"})).json()
    await _put(client, h, env_id, "TOKEN", "v2")
    gate = Gate("restore")
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated("restore", client.post(f"{base}/snapshots/{snap['id']}/restore", headers=h), gate)
    assert (await client.delete(f"{base}/snapshots/{snap['id']}", headers=h)).status_code == 204
    gate.release.set()
    assert (await task).status_code == 404
    names = {r["name"] for r in (await client.get(f"{base}/secrets", headers=h)).json()}
    assert names == {"DB_URL", "API_KEY", "TOKEN"}
    assert (await _read(client, h, env_id, "TOKEN")).json()["value"] == "v2"


async def test_agent_read_survives_a_concurrent_rename(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    h, base = owner_headers, f"/api/environments/{env_id}"
    await _put(client, h, env_id, "X", "v")
    agent = await _bearer(client, await _machine(client, h, env_id))
    gate = Gate("agent")
    gate_async(monkeypatch, secrets_store, "values_of", gate)
    task = await _gated("agent", client.get("/api/v1/machine/secrets", headers=agent, params={"project": "billing", "env": "prod"}), gate)
    assert (await client.post(f"{base}/secret/rename", headers=h, json={"name": "X", "new_name": "Y"})).status_code == 200
    gate.release.set()
    res = await task
    assert getattr(res, "status_code", res) == 200


# Ворота держат включение посреди транзакции: на Postgres его блокировки
# остановили бы запись, которую тест ждет до открытия ворот. Там это
# проверяет test_pg_races.test_pg_race_e2e_init_vs_plain_write.
@pytest.mark.skipif(bool(PG), reason="на Postgres - test_pg_races")
async def test_e2e_switch_does_not_swallow_a_plain_write(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    """Включение проверило "проект пуст", а открытый текст закоммитился до его
    коммита: режим не включается поверх открытого значения."""
    h = owner_headers
    project = (await client.post("/api/projects", headers=h, json={"slug": "sealed-app"})).json()
    env = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "prod"})).json()
    gate = Gate("init")
    gate_async(monkeypatch, audit, "record", gate)
    task = await _gated("init", client.post(f"/api/projects/{project['id']}/e2e", headers=h, json=_wrap_body()), gate)
    await _put(client, h, env["id"], "DB", "plain-text")
    gate.release.set()
    assert (await task).status_code == 400
    assert (await client.get(f"/api/projects/{project['id']}/e2e", headers=h)).json()["enabled"] is False


# --- окружения, сейф, журнал -----------------------------------------------------


async def test_two_parent_edits_cannot_make_a_cycle(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    h = owner_headers
    project_id = (await client.get("/api/projects", headers=h)).json()[0]["id"]
    stage = (await client.post(f"/api/projects/{project_id}/environments", headers=h, json={"name": "stage"})).json()["id"]
    gate = Gate("first")
    gate_async(monkeypatch, secrets_store, "lock_env", gate)
    task = await _gated("first", client.patch(f"/api/environments/{env_id}", headers=h, json={"parent_id": stage}), gate)
    assert (await client.patch(f"/api/environments/{stage}", headers=h, json={"parent_id": env_id})).status_code == 200
    gate.release.set()
    assert (await task).status_code == 400
    parents = {e["id"]: e["parent_id"] for e in (await client.get(f"/api/projects/{project_id}/environments", headers=h)).json()}
    assert not (parents[env_id] == stage and parents[stage] == env_id)


async def test_same_environment_twice_is_409(client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch):
    h = owner_headers
    project = (await client.post("/api/projects", headers=h, json={"slug": "app"})).json()
    url = f"/api/projects/{project['id']}/environments"
    gate = Gate("second")
    gate_async(monkeypatch, projects_api, "_check_parent", gate)
    task = await _gated("second", client.post(url, headers=h, json={"name": "qa"}), gate)
    assert (await client.post(url, headers=h, json={"name": "qa"})).status_code == 201
    gate.release.set()
    res = await task
    assert getattr(res, "status_code", res) == 409


async def test_seal_during_root_rotation_stays_sealed(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    h = owner_headers
    await _put(client, h, env_id, "K", "v")
    gate = Gate("rotate")
    gate_async(monkeypatch, envkeys, "rewrap_for_new_root", gate)
    task = await _gated("rotate", client.post("/api/vault/rotate-root", headers=h), gate)
    assert (await client.post("/api/vault/seal", headers=h)).json()["sealed"] is True
    gate.release.set()
    res = await task
    assert res.status_code == 200, res.text
    assert (await client.get("/api/vault/status", headers=h)).json()["sealed"] is True
    # Новый ключ, показанный при смене, и отпирает панель.
    assert (await client.post("/api/vault/unseal", headers=h, json={"root_key": res.json()["root_key"]})).status_code == 200
    assert (await _read(client, h, env_id, "K")).json()["value"] == "v"


async def test_row_changes_go_before_the_journal_lock(client: httpx.AsyncClient, owner_headers, env_id, monkeypatch):
    """Правка строки уходит в базу до блокировки журнала, а не на коммите после
    нее: обратный порядок в разных маршрутах давал встречное ожидание."""
    app = client._transport.app
    log: list[str] = []

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, params, context, executemany):
        log.append(" ".join(statement.split()))

    real = audit._lock

    async def marked(session):
        log.append("<journal lock>")
        await real(session)

    monkeypatch.setattr(audit, "_lock", marked)
    for path, body in (
        (f"/api/environments/{env_id}", {"title": "Prod!"}),
    ):
        log.clear()
        assert (await client.patch(path, headers=owner_headers, json=body)).status_code == 200
        update = next(i for i, s in enumerate(log) if s.startswith("UPDATE environments"))
        assert update < log.index("<journal lock>")


# --- вход ----------------------------------------------------------------------


async def test_login_burst_checks_at_most_the_limit(client: httpx.AsyncClient, owner_headers):
    async def attempt(i):
        return await run_safely(client.post("/api/auth/login", json={"username": "owner", "password": f"wrong-{i}"}))

    results = await asyncio.gather(*[attempt(i) for i in range(30)])
    codes = [getattr(r, "status_code", r) for r in results]
    assert codes.count(401) <= ratelimit.MAX_FAILURES, codes


async def test_guessing_the_code_locks_the_account(client: httpx.AsyncClient, owner_headers, unsealed):
    """Пароль известен, код подбирают: после нескольких неверных кодов вход
    заперт на учетку, и верный код тоже получает 429."""
    await _user(client, owner_headers, "dev", "developer")
    dev = await login(client, "dev", PASS)
    secret = (await client.post("/api/auth/2fa/start", headers=dev)).json()["secret"]
    now = totp.counter_now(time.time())
    code = totp._code(secret, now)
    assert (await client.post("/api/auth/2fa/enable", headers=dev, json={"password": PASS, "code": code})).status_code == 200
    right = totp._code(secret, now + 1)
    wrong = "000000" if right != "000000" else "111111"
    for _ in range(auth_api.OTP_LIMIT):
        res = await client.post("/api/auth/login", json={"username": "dev", "password": PASS, "otp": wrong})
        assert res.status_code == 401, res.text
    res = await client.post("/api/auth/login", json={"username": "dev", "password": PASS, "otp": right})
    assert res.status_code == 429, res.text


# --- машины ----------------------------------------------------------------------


async def test_enroll_token_dies_with_its_creator_rights(client: httpx.AsyncClient, owner_headers, env_id):
    lead_id = await _user(client, owner_headers, "lead", "maintainer")
    await _pol(client, owner_headers, lead_id, env_id, "/", ["list", "read"])
    lead = await login(client, "lead", PASS)
    first = (await client.post("/api/machines/enroll-token", headers=lead, json={"environment_id": env_id})).json()["token"]
    second = (await client.post("/api/machines/enroll-token", headers=lead, json={"environment_id": env_id})).json()["token"]
    # Окружение у автора отняли: его токен больше не выдает это окружение.
    for policy in (await client.get("/api/policies", headers=owner_headers)).json():
        if policy.get("subject_type") == "user" and policy.get("subject_id") == lead_id:
            assert (await client.delete(f"/api/policies/{policy['id']}", headers=owner_headers)).status_code in (200, 204)
    res = await client.post("/api/v1/machine/enroll", json={"token": first, "hostname": "web-1"})
    assert res.status_code == 401, res.text
    # Учетку отключили - тем более.
    assert (await client.patch(f"/api/users/{lead_id}", headers=owner_headers, json={"disabled": True})).status_code == 200
    res = await client.post("/api/v1/machine/enroll", json={"token": second, "hostname": "web-2"})
    assert res.status_code == 401, res.text


async def test_machine_token_does_not_fit_a_new_machine_with_the_same_number(client: httpx.AsyncClient, owner_headers, env_id):
    h = owner_headers
    old = await _machine(client, h, env_id, name="old")
    token = await _bearer(client, old)
    res = await client.delete(f"/api/machines/{old['id']}", headers=h, params={"confirm": "old"})
    assert res.status_code == 204, res.text
    new = await _machine(client, h, env_id, name="new")
    # SQLite отдает освободившийся номер, Postgres - нет (там и случая нет);
    # проверка отказа нужна в обоих.
    assert new["id"] == old["id"] or PG
    res = await client.get("/api/v1/machine/secrets", headers=token, params={"project": "billing", "env": "prod"})
    assert res.status_code == 401, res.text


async def test_basic_refusal_goes_to_the_journal(client: httpx.AsyncClient, owner_headers, env_id):
    machine = await _machine(client, owner_headers, env_id)
    pair = base64.b64encode(f"{machine['client_id']}:wrong-secret".encode()).decode()
    res = await client.get(
        "/api/v1/machine/secrets", headers={"Authorization": "Basic " + pair}, params={"project": "billing", "env": "prod"}
    )
    assert res.status_code == 401
    app = client._transport.app
    async with app.state.session_factory() as session:
        targets = list(await session.scalars(select(AuditLog.target).where(AuditLog.action == "machine_denied")))
    assert "basic" in targets


async def test_enroll_token_address_is_checked(client: httpx.AsyncClient, owner_headers, unsealed):
    res = await client.post("/api/machines/enroll-token", headers=owner_headers, json={"allow_ips": "10.0.0.300"})
    assert res.status_code == 400, res.text


async def test_deleting_a_machine_needs_its_reach(client: httpx.AsyncClient, owner_headers, env_id):
    machine = await _machine(client, owner_headers, env_id, name="prod-node")
    await _user(client, owner_headers, "lead", "maintainer")
    lead = await login(client, "lead", PASS)
    res = await client.delete(f"/api/machines/{machine['id']}", headers=lead, params={"confirm": "prod-node"})
    assert res.status_code == 403, res.text


async def test_machine_wrap_needs_its_reach(client: httpx.AsyncClient, owner_headers, unsealed):
    h = owner_headers
    project = (await client.post("/api/projects", headers=h, json={"slug": "vault3", "environments": ["dev", "prod"]})).json()
    envs = {e["name"]: e["id"] for e in (await client.get(f"/api/projects/{project['id']}/environments", headers=h)).json()}
    assert (await client.post(f"/api/projects/{project['id']}/e2e", headers=h, json=_wrap_body())).status_code == 200
    machine = await _machine(client, h, envs["prod"], name="prod-node")
    agent = await _bearer(client, machine)
    public = base64.b64encode(b"k" * 32).decode()
    assert (await client.post("/api/v1/machine/report", headers=agent, json={"public_key": public})).status_code == 200
    lead_id = await _user(client, h, "lead", "maintainer")
    await _pol(client, h, lead_id, envs["dev"], "/", ["list", "read", "write"])
    lead = await login(client, "lead", PASS)
    wrapped = {
        "machine_id": machine["id"],
        "ephemeral_public": base64.b64encode(b"e" * 32).decode(),
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "wrapped_key": base64.b64encode(b"w" * 48).decode(),
    }
    res = await client.post(f"/api/projects/{project['id']}/e2e/machines", headers=lead, json=wrapped)
    assert res.status_code == 403, res.text


# --- имена ключей ------------------------------------------------------------------


async def test_names_compose_cannot_read_are_refused(client: httpx.AsyncClient, owner_headers, env_id):
    for bad in ("smtp/host", "a:b", "user@host", "price$"):
        res = await client.put(f"/api/environments/{env_id}/secrets", headers=owner_headers, json={"name": bad, "value": "v"})
        assert res.status_code == 400, (bad, res.text)
    for good in ("spring.datasource.url", "my-key", "ПАРОЛЬ_БД", "A1"):
        await _put(client, owner_headers, env_id, good, "v")
