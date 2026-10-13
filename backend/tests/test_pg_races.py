"""Настоящие гонки на Postgres: параллельные запросы без ворот, блокировки базы.

Только для прогона на стенде (SEKVYR_TEST_PG). Каждый сценарий - несколько
раундов asyncio.gather; 5xx - провал, 409 (повтор/встречная блокировка)
допустимы, но печатаются.
"""

import asyncio
import collections
import os

import httpx
import pytest
from sqlalchemy import func, select

from app.models import MachineApp, Secret, SecretVersion, User
from tests.conftest import PG
from tests.test_pass8b_backend import PASS, _user
from tests.test_pass9_backend import _bearer, _machine, _wrap_body

pytestmark = pytest.mark.skipif(not PG and not os.environ.get("RACES_ANYDB"), reason="нужен SEKVYR_TEST_PG")

STATS: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)


def _code(res):
    return getattr(res, "status_code", repr(res)[:120])


async def _safe(coro):
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001
        return exc


def _check(name, results, allowed=(200, 201, 204, 409)):
    codes = [_code(r) for r in results]
    STATS[name].update(codes)
    bad = [(c, getattr(r, "text", "")[:300]) for c, r in zip(codes, results) if c not in allowed]
    assert not bad, f"{name}: {bad}"
    return codes


def _app(client):
    return client._transport.app


async def _put(client, h, env, name, value, path="/"):
    return await client.put(f"/api/environments/{env}/secrets", headers=h, json={"name": name, "value": value, "path": path})


async def _one_current_per_key(client):
    async with _app(client).state.session_factory() as session:
        rows = (
            await session.execute(
                select(SecretVersion.secret_id, func.count())
                .where(SecretVersion.status == "current")
                .group_by(SecretVersion.secret_id)
                .having(func.count() > 1)
            )
        ).all()
        dup = (
            await session.execute(
                select(SecretVersion.secret_id, SecretVersion.version, func.count())
                .group_by(SecretVersion.secret_id, SecretVersion.version)
                .having(func.count() > 1)
            )
        ).all()
    assert not rows, f"две текущие версии: {rows}"
    assert not dup, f"один номер версии дважды: {dup}"


async def test_pg_race_writes_rotate_and_machine_reads(client: httpx.AsyncClient, owner_headers, env_id):
    h = owner_headers
    machine = await _machine(client, h, env_id)
    token = await _bearer(client, machine)
    for i in range(5):
        assert (await _put(client, h, env_id, f"K{i}", "v0")).status_code == 200
    last: dict[str, str] = {}
    for rnd in range(8):
        calls = []
        for i in range(5):
            calls.append(_put(client, h, env_id, f"K{i}", f"v{rnd}"))
        calls.append(client.post(f"/api/environments/{env_id}/rotate-key", headers=h))
        calls.append(client.post(f"/api/environments/{env_id}/rotate-key", headers=h))
        for _ in range(3):
            calls.append(client.get("/api/v1/machine/env", headers=token, params={"project": "billing", "env": "prod"}))
        calls.append(client.get(f"/api/environments/{env_id}/secret", headers=h, params={"name": "K1"}))
        results = await asyncio.gather(*[_safe(c) for c in calls])
        _check("writes+rotate+reads", results)
        for i in range(5):
            if _code(results[i]) == 200:
                last[f"K{i}"] = f"v{rnd}"
    for name in [f"K{i}" for i in range(5)]:
        res = await client.get(f"/api/environments/{env_id}/secret", headers=h, params={"name": name})
        assert res.status_code == 200, res.text
        assert res.json()["value"] == last[name]
    res = await client.get("/api/v1/machine/env", headers=token, params={"project": "billing", "env": "prod"})
    assert res.status_code == 200 and all(f"K{i}" in res.text for i in range(5)), res.text
    await _one_current_per_key(client)


async def test_pg_race_same_new_key_twice(client: httpx.AsyncClient, owner_headers, env_id):
    for rnd in range(10):
        results = await asyncio.gather(*[_safe(_put(client, owner_headers, env_id, f"NEW{rnd}", f"x{i}")) for i in range(4)])
        _check("same new key", results)
    async with _app(client).state.session_factory() as session:
        dup = (
            await session.execute(
                select(Secret.path, Secret.name, func.count()).group_by(Secret.environment_id, Secret.path, Secret.name).having(func.count() > 1)
            )
        ).all()
    assert not dup
    await _one_current_per_key(client)


async def test_pg_race_e2e_init_vs_plain_write(client: httpx.AsyncClient, owner_headers, unsealed):
    h = owner_headers
    outcomes = collections.Counter()
    for rnd in range(12):
        project = (await client.post("/api/projects", headers=h, json={"slug": f"sealed-{rnd}"})).json()
        env = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "prod"})).json()
        stage = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "stage"})).json()
        calls = [
            client.post(f"/api/projects/{project['id']}/e2e", headers=h, json=_wrap_body()),
            _put(client, h, env["id"], "DB", "plain-text"),
            _put(client, h, stage["id"], "DB2", "plain-text"),
        ]
        if rnd % 2:
            calls.reverse()
        results = await asyncio.gather(*[_safe(c) for c in calls])
        if rnd % 2:
            results.reverse()
        codes = _check("e2e init vs put", results, allowed=(200, 400, 409))
        outcomes[tuple(codes)] += 1
        enabled = (await client.get(f"/api/projects/{project['id']}/e2e", headers=h)).json()["enabled"]
        plain = any(c == 200 for c in codes[1:])
        assert not (enabled and plain), f"режим включен поверх открытого текста: {codes}"
    print("e2e outcomes", dict(outcomes))


async def test_pg_race_rename_everywhere_vs_writes(client: httpx.AsyncClient, owner_headers, unsealed):
    h = owner_headers
    project = (await client.post("/api/projects", headers=h, json={"slug": "multi"})).json()
    envs = [
        (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": n})).json()["id"]
        for n in ("dev", "stage", "prod")
    ]
    for rnd in range(6):
        old, new = f"X{rnd}", f"Y{rnd}"
        for env in envs:
            assert (await _put(client, h, env, old, "1")).status_code == 200
        calls = [
            client.post(f"/api/environments/{envs[0]}/secret/rename", headers=h,
                        json={"name": old, "new_name": new, "everywhere": True}),
            _put(client, h, envs[1], old, "2"),
            _put(client, h, envs[2], old, "3"),
            _put(client, h, envs[2], new, "4"),
            client.post(f"/api/environments/{envs[1]}/secret/rename", headers=h,
                        json={"name": old, "new_name": f"Z{rnd}"}),
        ]
        results = await asyncio.gather(*[_safe(c) for c in calls])
        _check("rename everywhere vs writes", results, allowed=(200, 400, 404, 409))
    for env in envs:
        res = await client.get(f"/api/environments/{env}/secrets", headers=h)
        assert res.status_code == 200, res.text
        names = [(s["path"], s["name"]) for s in res.json()]
        assert len(names) == len(set(names)), names
        for path, name in names:
            got = await client.get(f"/api/environments/{env}/secret", headers=h, params={"name": name, "path": path})
            assert got.status_code in (200, 404), got.text
    await _one_current_per_key(client)


async def test_pg_race_parent_edits(client: httpx.AsyncClient, owner_headers, unsealed):
    h = owner_headers
    project = (await client.post("/api/projects", headers=h, json={"slug": "tree"})).json()
    a = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "a"})).json()["id"]
    b = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "b"})).json()["id"]
    for rnd in range(10):
        results = await asyncio.gather(
            _safe(client.patch(f"/api/environments/{a}", headers=h, json={"parent_id": b, "title": f"a{rnd}"})),
            _safe(client.patch(f"/api/environments/{b}", headers=h, json={"parent_id": a, "title": f"b{rnd}"})),
        )
        _check("parent edits", results, allowed=(200, 400, 409))
        envs = {e["id"]: e["parent_id"] for e in (await client.get(f"/api/projects/{project['id']}/environments", headers=h)).json()}
        assert not (envs[a] == b and envs[b] == a), "круг наследования"
        for env in (a, b):
            assert (await client.patch(f"/api/environments/{env}", headers=h, json={"parent_id": None})).status_code == 200


async def test_pg_race_token_version_bumps(client: httpx.AsyncClient, owner_headers, unsealed):
    h = owner_headers
    dev_id = await _user(client, h, "dev", "developer")
    async with _app(client).state.session_factory() as session:
        before = await session.scalar(select(User.token_version).where(User.id == dev_id))
    results = await asyncio.gather(*[
        _safe(client.post(f"/api/users/{dev_id}/password", headers=h, json={"new_password": f"{PASS}-{i}"}))
        for i in range(6)
    ])
    codes = _check("password resets", results, allowed=(204, 409))
    async with _app(client).state.session_factory() as session:
        after = await session.scalar(select(User.token_version).where(User.id == dev_id))
    assert after - before == codes.count(204), (before, after, codes)


async def test_pg_race_first_report_of_two_pods(client: httpx.AsyncClient, owner_headers, env_id):
    machine = await _machine(client, owner_headers, env_id)
    token = await _bearer(client, machine)
    from sqlalchemy import delete

    for rnd in range(5):
        async with _app(client).state.session_factory() as session:
            await session.execute(delete(MachineApp))
            await session.commit()
        body = {"agent_version": "1.0.0", "applied": f"v{rnd}", "project": "billing", "env": "prod", "path": f"/srv/{rnd}/.env"}
        results = await asyncio.gather(*[_safe(client.post("/api/v1/machine/report", headers=token, json=body)) for _ in range(5)])
        _check("pods report", results, allowed=(200,))
    async with _app(client).state.session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(MachineApp)) == 1
        dup = (
            await session.execute(
                select(MachineApp.machine_id, MachineApp.project_slug, MachineApp.env_name, func.count())
                .group_by(MachineApp.machine_id, MachineApp.group_slug, MachineApp.project_slug, MachineApp.env_name)
                .having(func.count() > 1)
            )
        ).all()
    assert not dup


async def test_pg_race_snapshot_restore_vs_writes(client: httpx.AsyncClient, owner_headers, env_id):
    h = owner_headers
    for i in range(4):
        assert (await _put(client, h, env_id, f"S{i}", "old")).status_code == 200
    snap = (await client.post(f"/api/environments/{env_id}/snapshots", headers=h, json={"name": "base"})).json()["id"]
    for rnd in range(6):
        calls = [
            client.post(f"/api/environments/{env_id}/snapshots/{snap}/restore", headers=h),
            _put(client, h, env_id, "S0", f"new{rnd}"),
            _put(client, h, env_id, f"EXTRA{rnd}", "e"),
            client.post(f"/api/environments/{env_id}/rotate-key", headers=h),
            client.request("DELETE", f"/api/environments/{env_id}/secret", headers=h, params={"name": "S1"}),
        ]
        results = await asyncio.gather(*[_safe(c) for c in calls])
        _check("restore vs writes", results, allowed=(200, 204, 404, 409))
    res = await client.get(f"/api/environments/{env_id}/values", headers=h)
    assert res.status_code == 200, res.text
    await _one_current_per_key(client)


async def test_pg_race_project_delete_vs_writes(client: httpx.AsyncClient, owner_headers, unsealed):
    h = owner_headers
    for rnd in range(6):
        project = (await client.post("/api/projects", headers=h, json={"slug": f"gone-{rnd}"})).json()
        env = (await client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "prod"})).json()["id"]
        assert (await _put(client, h, env, "A", "1")).status_code == 200
        calls = [
            client.delete(f"/api/projects/{project['id']}", headers=h, params={"confirm": f"gone-{rnd}"}),
            _put(client, h, env, "A", "2"),
            _put(client, h, env, "B", "3"),
            client.post(f"/api/environments/{env}/rotate-key", headers=h),
            client.post(f"/api/projects/{project['id']}/environments", headers=h, json={"name": "stage", "copy_from": env}),
        ]
        results = await asyncio.gather(*[_safe(c) for c in calls])
        _check("delete project vs writes", results, allowed=(200, 201, 204, 400, 404, 409))


def test_pg_race_zz_stats():
    for name, counter in STATS.items():
        print(f"{name}: {dict(counter)}")
