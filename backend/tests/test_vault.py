"""Корневой ключ: заведение, отпирание, запирание, ротация."""

import asyncio
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import alerts, config, sealbox, secrets_store
from app.cli import _mark_multiline
from app.main import _auto_unseal, create_app
from app.models import AppSetting, AuditLog, EnvKey, SecretVersion, User
from app.security import create_access_token
from tests.conftest import login


async def prepare_rotation(client, headers):
    res = await client.post("/api/vault/rotate-root/prepare", headers=headers)
    assert res.status_code == 200
    assert res.headers["Cache-Control"] == "no-store"
    return res.json()


async def prepare_init(client, headers, options):
    res = await client.post("/api/vault/init/prepare", headers=headers, json=options)
    assert res.status_code == 200
    assert res.headers["Cache-Control"] == "no-store"
    material = res.json()
    assert material["mode"] == options["mode"] and material["warning"]
    return {key: material[key] for key in ("root_key", "shares", "proof")}


async def test_starts_sealed_and_uninitialized(client: httpx.AsyncClient, owner_headers):
    res = await client.get("/api/vault/status", headers=owner_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["initialized"] is False
    assert body["sealed"] is True


async def test_health_shows_sealed(client: httpx.AsyncClient):
    """Снаружи должно быть видно, что панель жива, но значений не отдает."""
    body = (await client.get("/api/health")).json()
    assert body["sealed"] is True
    assert body["status"] == "sealed"


async def test_init_commit_failure_keeps_vault_sealed(client, owner_headers, monkeypatch):
    async def fail_commit(session):
        await session.rollback()
        raise RuntimeError("simulated commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(AsyncSession, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="simulated commit failure"):
            await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})

    state = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert state["initialized"] is False
    assert state["sealed"] is True

    retried = await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    assert retried.status_code == 200
    state = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert state["initialized"] is True
    assert state["sealed"] is False


@pytest.mark.parametrize("mode", ["env", "shares"])
async def test_prepared_init_survives_losing_commit_reply(client, owner_headers, monkeypatch, mode):
    options = {"mode": mode, "shares": 3, "threshold": 2, "auto_unseal": mode == "env"}
    prepared = await prepare_init(client, owner_headers, options)
    other = await prepare_init(client, owner_headers, options)
    if mode == "shares":
        assert prepared["root_key"] == "" and len(prepared["shares"]) == 3
        tampered = {**prepared, "shares": prepared["shares"][::-1]}
    else:
        assert prepared["root_key"] and prepared["shares"] == []
        tampered = {**prepared, "root_key": prepared["root_key"] + " "}

    app = client._transport.app
    async with app.state.session_factory() as session:
        assert not await session.scalar(select(AppSetting.key).where(AppSetting.key.startswith("vault_")))
        assert not await session.scalar(select(AuditLog.id).where(AuditLog.action == "vault_initialized"))
    assert not app.state.sealbox.unsealed

    for invalid in (
        {**options, "prepared": tampered},
        {**options, "prepared": {**prepared, "proof": "0" * 64}},
        {**options, "auto_unseal": not options["auto_unseal"], "prepared": prepared},
    ):
        rejected = await client.post("/api/vault/init", headers=owner_headers, json=invalid)
        assert rejected.status_code == 400
    body = {**options, "prepared": prepared}
    committed, resume = asyncio.Event(), asyncio.Event()
    commit = AsyncSession.commit

    async def pause_after_commit(session):
        await commit(session)
        committed.set()
        await resume.wait()

    with monkeypatch.context() as patch:
        patch.setattr(AsyncSession, "commit", pause_after_commit)
        request = asyncio.create_task(client.post("/api/vault/init", headers=owner_headers, json=body))
        try:
            await asyncio.wait_for(committed.wait(), timeout=5)
            request.cancel()
            await asyncio.sleep(0)
        finally:
            resume.set()
            outcome, = await asyncio.gather(request, return_exceptions=True)
    assert isinstance(outcome, asyncio.CancelledError)

    app = create_app()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as restarted:
            repeated = await restarted.post("/api/vault/init", headers=owner_headers, json=body)
            assert repeated.status_code == 200
            assert repeated.headers["Cache-Control"] == "no-store"
            assert repeated.json() == {"mode": mode, "root_key": "", "shares": [], "warning": ""}
            assert not app.state.sealbox.unsealed
            rejected = await restarted.post("/api/vault/init", headers=owner_headers,
                                            json={**options, "prepared": other})
            assert rejected.status_code == 409
            assert (await restarted.post("/api/vault/init/prepare", headers=owner_headers,
                                         json=options)).status_code == 409

            material = ([{"share": value} for value in prepared["shares"][1:]]
                        if mode == "shares" else [{"root_key": prepared["root_key"]}])
            for item in material:
                opened = await restarted.post("/api/vault/unseal", headers=owner_headers, json=item)
                assert opened.status_code == 200
            assert not opened.json()["sealed"]
            rotated = await restarted.post("/api/vault/rotate-root", headers=owner_headers,
                                           json=await prepare_rotation(restarted, owner_headers))
            assert rotated.status_code == 200
            assert (await restarted.post("/api/vault/init", headers=owner_headers, json=body)).status_code == 409
        async with app.state.session_factory() as session:
            initialized = list(await session.scalars(select(AuditLog.id).where(AuditLog.action == "vault_initialized")))
            assert len(initialized) == 1
    finally:
        await app.state.engine.dispose()


async def test_prepared_init_is_bound_to_the_owner(client, owner_headers):
    options = {"mode": "env"}
    prepared = await prepare_init(client, owner_headers, options)
    app = client._transport.app
    async with app.state.session_factory() as session:
        other = User(username="other-owner", password_hash="unused", role="owner")
        session.add(other)
        await session.commit()
    settings = config.get_settings()
    token = create_access_token(other.username, settings.jwt_secret, settings.jwt_ttl_minutes)
    body = {**options, "prepared": prepared}
    rejected = await client.post("/api/vault/init", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert rejected.status_code == 400
    assert not app.state.sealbox.unsealed
    confirmed = await client.post("/api/vault/init", headers=owner_headers, json=body)
    assert confirmed.status_code == 200
    assert app.state.sealbox.unsealed


async def test_init_with_shares_and_unseal(client: httpx.AsyncClient, owner_headers):
    res = await client.post(
        "/api/vault/init",
        headers=owner_headers,
        json={"mode": "shares", "shares": 5, "threshold": 3},
    )
    assert res.status_code == 200, res.text
    shares = res.json()["shares"]
    assert len(shares) == 5
    assert res.json()["root_key"] == ""  # в режиме долей ключ целиком не показываем

    # после заведения панель открыта
    assert (await client.get("/api/vault/status", headers=owner_headers)).json()["sealed"] is False

    # запираем и собираем заново из трех долей
    assert (await client.post("/api/vault/seal", headers=owner_headers)).status_code == 200
    first = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": shares[0]})
    assert first.json()["sealed"] is True
    assert first.json()["pending_shares"] == 1
    second = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": shares[2]})
    assert second.json()["sealed"] is True
    third = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": shares[4]})
    assert third.json()["sealed"] is False


async def test_same_share_does_not_count_twice(client: httpx.AsyncClient, owner_headers):
    res = await client.post(
        "/api/vault/init",
        headers=owner_headers,
        json={"mode": "shares", "shares": 5, "threshold": 3},
    )
    shares = res.json()["shares"]
    await client.post("/api/vault/seal", headers=owner_headers)
    for _ in range(4):
        out = await client.post(
            "/api/vault/unseal", headers=owner_headers, json={"share": shares[0]}
        )
    assert out.json()["sealed"] is True
    assert out.json()["pending_shares"] == 1


async def test_foreign_share_is_refused(client: httpx.AsyncClient, owner_headers):
    """Доля от другого сейфа не должна ни отпирать, ни копиться."""
    from app import shamir

    await client.post(
        "/api/vault/init", headers=owner_headers, json={"mode": "shares", "shares": 3, "threshold": 2}
    )
    await client.post("/api/vault/seal", headers=owner_headers)
    alien = shamir.split(b"\x01" * 32, shares=3, threshold=2)
    res = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": alien[0]})
    assert res.status_code == 200  # доля принята как "одна из"...
    res = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": alien[1]})
    # ...но собранный из чужих долей ключ не сходится с маркером
    assert res.status_code == 400
    assert (await client.get("/api/vault/status", headers=owner_headers)).json()["sealed"] is True


async def test_cannot_init_twice(client: httpx.AsyncClient, owner_headers):
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    again = await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    assert again.status_code == 409


async def test_unseal_by_root_key(client: httpx.AsyncClient, owner_headers, unsealed):
    await client.post("/api/vault/seal", headers=owner_headers)
    bad = await client.post(
        "/api/vault/unseal", headers=owner_headers, json={"root_key": "AAAA"}
    )
    assert bad.status_code == 400
    good = await client.post(
        "/api/vault/unseal", headers=owner_headers, json={"root_key": unsealed}
    )
    assert good.json()["sealed"] is False


async def test_failed_unseal_commit_keeps_vault_sealed(client, owner_headers, unsealed, monkeypatch):
    await client.post("/api/vault/seal", headers=owner_headers)

    async def fail_commit(session):
        await session.rollback()
        raise RuntimeError("simulated commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(AsyncSession, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="simulated commit failure"):
            await client.post("/api/vault/unseal", headers=owner_headers, json={"root_key": unsealed})

    state = await client.get("/api/vault/status", headers=owner_headers)
    assert state.json()["sealed"] is True
    opened = await client.post("/api/vault/unseal", headers=owner_headers, json={"root_key": unsealed})
    assert opened.status_code == 200 and not opened.json()["sealed"]


@pytest.mark.parametrize("operation", ["init", "unseal"])
async def test_seal_wins_over_an_in_flight_open(client, owner_headers, monkeypatch, operation):
    body = {"mode": "env"}
    if operation == "unseal":
        initialized = await client.post("/api/vault/init", headers=owner_headers, json=body)
        assert initialized.status_code == 200
        body = {"root_key": initialized.json()["root_key"]}
        await client.post("/api/vault/seal", headers=owner_headers)
    committed, release = asyncio.Event(), asyncio.Event()
    commit = AsyncSession.commit

    async def pause_commit(session):
        await commit(session)
        if asyncio.current_task() is opening:
            committed.set()
            await release.wait()

    monkeypatch.setattr(AsyncSession, "commit", pause_commit)
    opening = asyncio.create_task(client.post(f"/api/vault/{operation}", headers=owner_headers, json=body))
    try:
        await asyncio.wait_for(committed.wait(), timeout=5)
        sealed = await client.post("/api/vault/seal", headers=owner_headers)
        assert sealed.status_code == 200 and sealed.json()["sealed"]
    finally:
        release.set()
        result = await opening

    assert result.status_code == 200
    if operation == "unseal":
        assert result.json()["sealed"] is True
    state = await client.get("/api/vault/status", headers=owner_headers)
    assert state.json()["sealed"] is True


async def test_seal_while_reading_an_environment_key_returns_503(client, owner_headers, env_id, monkeypatch):
    base = f"/api/environments/{env_id}"
    wrote = await client.put(base + "/secrets", headers=owner_headers,
                             json={"name": "CHECK", "value": "synthetic-value"})
    assert wrote.status_code == 200
    loaded, release = asyncio.Event(), asyncio.Event()
    scalar = AsyncSession.scalar

    async def pause_after_load(session, statement, *args, **kwargs):
        result = await scalar(session, statement, *args, **kwargs)
        if isinstance(result, EnvKey):
            loaded.set()
            await release.wait()
        return result

    monkeypatch.setattr(AsyncSession, "scalar", pause_after_load)
    read = asyncio.create_task(client.get(base + "/secret", headers=owner_headers, params={"name": "CHECK"}))
    try:
        await asyncio.wait_for(loaded.wait(), timeout=5)
        sealed = await client.post("/api/vault/seal", headers=owner_headers)
        assert sealed.status_code == 200 and sealed.json()["sealed"]
    finally:
        release.set()
        result = await read

    assert result.status_code == 503
    assert "synthetic-value" not in result.text


@pytest.mark.parametrize("endpoint, params", [
    ("/secret", {"name": "CHECK"}),
    ("/secret/version", {"name": "CHECK", "version": 1}),
    ("/export", {}),
    ("/values", {}),
])
async def test_seal_after_decryption_blocks_response(client, owner_headers, env_id, monkeypatch, endpoint, params):
    base = f"/api/environments/{env_id}"
    wrote = await client.put(base + "/secrets", headers=owner_headers,
                             json={"name": "CHECK", "value": "synthetic-value"})
    assert wrote.status_code == 200
    committed, release = asyncio.Event(), asyncio.Event()
    commit = AsyncSession.commit

    async def pause_commit(session):
        await commit(session)
        if asyncio.current_task() is read:
            committed.set()
            await release.wait()

    monkeypatch.setattr(AsyncSession, "commit", pause_commit)
    read = asyncio.create_task(client.get(base + endpoint, headers=owner_headers, params=params))
    try:
        await asyncio.wait_for(committed.wait(), timeout=5)
        sealed = await client.post("/api/vault/seal", headers=owner_headers)
        assert sealed.status_code == 200 and sealed.json()["sealed"]
    finally:
        release.set()
        result = await read

    assert result.status_code == 503
    assert "synthetic-value" not in result.text


@pytest.mark.parametrize("endpoint", ["/secrets", "/env"])
async def test_seal_after_machine_decryption_blocks_response(client, owner_headers, env_id, monkeypatch, endpoint):
    from tests.test_pass9_backend import _bearer, _machine

    wrote = await client.put(f"/api/environments/{env_id}/secrets", headers=owner_headers,
                             json={"name": "CHECK", "value": "synthetic-value"})
    assert wrote.status_code == 200
    agent = await _bearer(client, await _machine(client, owner_headers, env_id))
    committed, release = asyncio.Event(), asyncio.Event()
    commit = AsyncSession.commit

    async def pause_commit(session):
        await commit(session)
        if asyncio.current_task() is read:
            committed.set()
            await release.wait()

    monkeypatch.setattr(AsyncSession, "commit", pause_commit)
    read = asyncio.create_task(client.get(
        "/api/v1/machine" + endpoint, headers=agent, params={"project": "billing", "env": "prod"},
    ))
    try:
        await asyncio.wait_for(committed.wait(), timeout=5)
        sealed = await client.post("/api/vault/seal", headers=owner_headers)
        assert sealed.status_code == 200 and sealed.json()["sealed"]
    finally:
        release.set()
        result = await read

    assert result.status_code == 503
    assert "synthetic-value" not in result.text


async def test_only_owner_initializes_and_seals(client: httpx.AsyncClient, owner_headers):
    await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "boss", "password": "member-pass-2026", "role": "maintainer"},
    )
    boss = await login(client, "boss", "member-pass-2026")
    assert (await client.post("/api/vault/init", headers=boss, json={"mode": "env"})).status_code == 403
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    assert (await client.post("/api/vault/seal", headers=boss)).status_code == 403
    assert (await client.post("/api/vault/rotate-root/prepare", headers=boss)).status_code == 403
    # ...но подать долю ответственный может: доли раздают людям, а не ролям
    assert (await client.get("/api/vault/status", headers=boss)).status_code == 200


async def test_root_rotation_keeps_values_readable(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "prod-secret"},
    )
    prepared = await prepare_rotation(client, owner_headers)
    res = await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)
    assert res.status_code == 200, res.text
    assert res.json()["root_generation"] == 2
    assert res.json()["rewrapped_keys"] == 1

    value = await client.get(
        f"/api/environments/{env_id}/secret",
        headers=owner_headers,
        params={"name": "DB_PASSWORD"},
    )
    assert value.json()["value"] == "prod-secret"


async def test_prepare_rotation_keeps_current_material_until_confirmation(client, owner_headers, env_id, unsealed):
    app = client._transport.app
    async with app.state.session_factory() as session:
        previous = await sealbox.read_meta(session)
    prepared = await prepare_rotation(client, owner_headers)
    assert prepared["root_generation"] == previous.generation
    assert prepared["root_key"] != unsealed and prepared["shares"] == []
    assert app.state.sealbox.root() == sealbox.unb64(unsealed)

    for tampered in (
        {**prepared, "proof": "0" * 64},
        {**prepared, "root_key": unsealed},
        {**prepared, "shares": ["invalid"]},
    ):
        refused = await client.post("/api/vault/rotate-root", headers=owner_headers, json=tampered)
        assert refused.status_code == 400
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers)).status_code == 409
    async with app.state.session_factory() as session:
        assert await sealbox.read_meta(session) == previous
        assert await session.scalar(select(AuditLog.id).where(AuditLog.action == "vault_root_rotated")) is None

    committed = await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)
    assert committed.status_code == 200
    assert committed.json() == {"root_generation": 2, "rewrapped_keys": 1, "root_key": "", "shares": []}


async def test_prepared_proof_binds_every_share(client, owner_headers):
    initialized = await client.post("/api/vault/init", headers=owner_headers,
                                    json={"mode": "shares", "shares": 3, "threshold": 2})
    assert initialized.status_code == 200
    prepared = await prepare_rotation(client, owner_headers)
    assert len(prepared["shares"]) == 3 and prepared["root_key"] == ""
    reordered = {**prepared, "shares": prepared["shares"][::-1]}
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers, json=reordered)).status_code == 400
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)).status_code == 200


@pytest.mark.parametrize("mode", ["env", "shares"])
async def test_prepared_rotation_can_be_retried_after_losing_commit_reply(
    client, owner_headers, monkeypatch, mode,
):
    initialized = await client.post("/api/vault/init", headers=owner_headers,
                                    json={"mode": mode, "shares": 3, "threshold": 2})
    assert initialized.status_code == 200
    project = await client.post("/api/projects", headers=owner_headers,
                                json={"slug": "rotation-test", "environments": ["prod"]})
    assert project.status_code == 201
    envs = await client.get(f"/api/projects/{project.json()['id']}/environments", headers=owner_headers)
    base = f"/api/environments/{envs.json()[0]['id']}"
    wrote = await client.put(base + "/secrets", headers=owner_headers,
                             json={"name": "CHECK", "value": "synthetic-value"})
    assert wrote.status_code == 200

    prepared = await prepare_rotation(client, owner_headers)
    committed, resume = asyncio.Event(), asyncio.Event()
    real_commit = AsyncSession.commit

    async def pause_after_commit(session):
        await real_commit(session)
        committed.set()
        await resume.wait()

    with monkeypatch.context() as patch:
        patch.setattr(AsyncSession, "commit", pause_after_commit)
        request = asyncio.create_task(client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared))
        try:
            await asyncio.wait_for(committed.wait(), timeout=5)
            request.cancel()
            await asyncio.sleep(0)
        finally:
            resume.set()
            outcome, = await asyncio.gather(request, return_exceptions=True)
    assert isinstance(outcome, asyncio.CancelledError)

    app = create_app()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as restarted:
            repeated = await restarted.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)
            assert repeated.status_code == 200
            assert repeated.json() == {"root_generation": 2, "rewrapped_keys": 0, "root_key": "", "shares": []}
            assert not app.state.sealbox.unsealed
            material = ([{"share": value} for value in prepared["shares"][:2]]
                        if mode == "shares" else [{"root_key": prepared["root_key"]}])
            for item in material:
                opened = await restarted.post("/api/vault/unseal", headers=owner_headers, json=item)
                assert opened.status_code == 200
            value = await restarted.get(base + "/secret", headers=owner_headers, params={"name": "CHECK"})
            assert value.status_code == 200 and value.json()["value"] == "synthetic-value"
        async with app.state.session_factory() as session:
            rotations = list(await session.scalars(select(AuditLog.id).where(AuditLog.action == "vault_root_rotated")))
            assert len(rotations) == 1
    finally:
        await app.state.engine.dispose()


async def test_new_environment_records_the_current_root_generation(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Окружение, заведенное после смены корневого ключа, записывалось с
    поколением 1, хотя обернуто ключом второго поколения."""
    from sqlalchemy import select

    from app.config import get_settings
    from app.db import create_engine_and_factory
    from app.models import EnvKey, Environment

    prepared = await prepare_rotation(client, owner_headers)
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)).status_code == 200
    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        project_id = (await session.get(Environment, env_id)).project_id
    made = await client.post(
        f"/api/projects/{project_id}/environments", headers=owner_headers, json={"name": "after"}
    )
    assert made.status_code in (200, 201), made.text
    async with factory() as session:
        row = await session.scalar(select(EnvKey).where(EnvKey.environment_id == made.json()["id"]))
        assert row.root_generation == 2
    await engine.dispose()


async def test_old_root_key_stops_working_after_rotation(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Прежний ключ после ротации бесполезен - иначе "ротация" ничего не меняет
    для того, у кого утек старый ключ."""
    prepared = await prepare_rotation(client, owner_headers)
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)).status_code == 200
    await client.post("/api/vault/seal", headers=owner_headers)
    res = await client.post(
        "/api/vault/unseal", headers=owner_headers, json={"root_key": unsealed}
    )
    assert res.status_code == 400


async def test_bad_share_counts_explain_themselves(client: httpx.AsyncClient, owner_headers):
    """Отказ должен приходить словами, а не как 422 со служебным списком: этот
    экран человек видит один раз в жизни и не должен угадывать, что ввел не так."""
    for body, expect in (
        ({"mode": "shares", "shares": 3, "threshold": 1}, "порог 1"),
        ({"mode": "shares", "shares": 1, "threshold": 1}, "хотя бы две"),
        ({"mode": "shares", "shares": 3, "threshold": 5}, "больше числа долей"),
    ):
        res = await client.post("/api/vault/init", headers=owner_headers, json=body)
        assert res.status_code == 400, (body, res.status_code, res.text)
        assert expect.lower() in res.json()["detail"].lower(), res.text
    # ни одна неудачная попытка не завела сейф наполовину
    assert (await client.get("/api/vault/status", headers=owner_headers)).json()["initialized"] is False


async def test_single_key_mode_remembers_the_intent(client: httpx.AsyncClient, owner_headers):
    """Панель запоминает, ждать ли ей ключ после перезапуска, и говорит, если
    намерение расходится с настройками. Иначе расхождение всплывает ровно в
    момент перезагрузки - когда его некому заметить."""
    res = await client.post(
        "/api/vault/init", headers=owner_headers, json={"mode": "env", "auto_unseal": True}
    )
    assert res.status_code == 200, res.text
    assert res.json()["root_key"]

    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["auto_unseal_intent"] is True
    # ключ в окружении не задан - панель должна это показывать
    assert status["root_key_configured"] is False


async def test_manual_key_mode_is_the_default(client: httpx.AsyncClient, owner_headers):
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["auto_unseal_intent"] is False


async def test_shares_mode_never_claims_auto_unseal(client: httpx.AsyncClient, owner_headers):
    """Доли и автоподъем несовместимы: собирать ключ из долей самому панель не
    умеет и не должна уметь."""
    await client.post(
        "/api/vault/init",
        headers=owner_headers,
        json={"mode": "shares", "shares": 3, "threshold": 2, "auto_unseal": True},
    )
    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["auto_unseal_intent"] is False


async def test_old_share_after_rotation_is_refused_cleanly(
    client: httpx.AsyncClient, owner_headers
):
    """Держатель подает долю от прежнего ключа: раньше это было 500 на каждой
    следующей доле, пока панель не перезапустят. Теперь отказ, набор
    сбрасывается, и новые доли открывают как обычно."""
    first = await client.post(
        "/api/vault/init", headers=owner_headers, json={"mode": "shares", "shares": 3, "threshold": 2}
    )
    old = first.json()["shares"]
    prepared = await prepare_rotation(client, owner_headers)
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)).status_code == 200
    fresh = prepared["shares"]
    await client.post("/api/vault/seal", headers=owner_headers)
    await client.post("/api/vault/unseal", headers=owner_headers, json={"share": old[0]})
    mixed = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": fresh[1]})
    assert mixed.status_code == 400, mixed.text
    status = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert status["sealed"] is True
    assert status.get("pending_shares", 0) == 0
    for share in fresh[:2]:
        out = await client.post("/api/vault/unseal", headers=owner_headers, json={"share": share})
    assert out.json()["sealed"] is False


async def test_rotation_rewrites_the_remembered_key(
    client: httpx.AsyncClient, owner_headers, tmp_path, monkeypatch
):
    """Ключ, запомненный на сервере, меняется вместе с корнем: иначе после
    перезапуска панель не отопрется, а новый ключ мог никто не сохранить."""
    from app import config

    key_file = tmp_path / "secret" / "root.key"
    monkeypatch.setenv("SEKVYR_ROOT_KEY_FILE", str(key_file))
    config.get_settings.cache_clear()
    await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env"})
    remembered = await client.post("/api/vault/remember-key", headers=owner_headers)
    assert remembered.status_code == 200, remembered.text
    before = key_file.read_text()
    rotated = await client.post("/api/vault/rotate-root", headers=owner_headers)
    assert rotated.status_code == 200, rotated.text
    after = key_file.read_text()
    assert after != before
    assert after == rotated.json()["root_key"]
    assert not (key_file.parent / "root.key.new").exists()


async def test_concurrent_empty_vault_rotations(client: httpx.AsyncClient, owner_headers, unsealed):
    async def rotate(prepared):
        return await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)

    candidates = [await prepare_rotation(client, owner_headers) for _ in range(2)]
    results = await asyncio.gather(*(rotate(prepared) for prepared in candidates))
    assert sorted(res.status_code for res in results) == [200, 409]
    generation_two = next(prepared for prepared, res in zip(candidates, results) if res.status_code == 200)
    generation_three = await prepare_rotation(client, owner_headers)
    assert (await rotate(generation_three)).json()["root_generation"] == 3

    headers = owner_headers
    assert (await client.post("/api/vault/seal", headers=headers)).json()["sealed"]
    stale = await client.post("/api/vault/unseal", headers=headers, json={"root_key": generation_two["root_key"]})
    assert stale.status_code == 400
    current = await client.post("/api/vault/unseal", headers=headers, json={"root_key": generation_three["root_key"]})
    assert current.status_code == 200 and not current.json()["sealed"]


@pytest.fixture
async def remembered_key(client, owner_headers, env_id, tmp_path, monkeypatch):
    path = tmp_path / "secret" / "root.key"
    monkeypatch.setenv("SEKVYR_ROOT_KEY_FILE", str(path))
    config.get_settings.cache_clear()
    assert (await client.post("/api/vault/remember-key", headers=owner_headers)).status_code == 200
    return path


async def _restart_and_check_root(root: bytes | None):
    settings = config.get_settings()
    app = create_app()
    try:
        await _auto_unseal(app, settings)
        box = app.state.sealbox
        assert box.unsealed == (root is not None)
        if root is not None:
            assert box.root() == root
    finally:
        await app.state.engine.dispose()


async def test_stale_key_files_do_not_report_auto_unseal(client, owner_headers, remembered_key):
    stale = remembered_key.read_text()
    rotated = await client.post("/api/vault/rotate-root", headers=owner_headers)
    assert rotated.status_code == 200
    remembered_key.write_text(stale)
    sealbox.staged_key_file(remembered_key).write_text(stale)

    state = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert state["key_file_present"] is True
    assert state["root_key_configured"] is False
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers)).status_code == 409
    await _restart_and_check_root(None)


async def test_rotation_with_stale_file_preserves_manual_share_mode(client, owner_headers, tmp_path, monkeypatch):
    path = tmp_path / "root.key"
    stale = sealbox.b64(bytes(32))
    path.write_text(stale)
    monkeypatch.setenv("SEKVYR_ROOT_KEY_FILE", str(path))
    config.get_settings.cache_clear()
    initialized = await client.post("/api/vault/init", headers=owner_headers,
                                    json={"mode": "shares", "shares": 3, "threshold": 2})
    assert initialized.status_code == 200

    prepared = await prepare_rotation(client, owner_headers)
    committed = await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)
    assert committed.status_code == 200
    assert path.read_text() == stale
    assert not sealbox.staged_key_file(path).exists()
    await _restart_and_check_root(None)


async def test_legacy_rotation_accepts_a_valid_staged_file(client, owner_headers, remembered_key):
    staged = sealbox.staged_key_file(remembered_key)
    remembered_key.replace(staged)
    rotated = await client.post("/api/vault/rotate-root", headers=owner_headers)
    assert rotated.status_code == 200
    assert not staged.exists()
    assert remembered_key.read_text() == rotated.json()["root_key"]
    await _restart_and_check_root(sealbox.unb64(remembered_key.read_text()))


async def test_startup_warns_when_the_configured_key_is_stale(client, owner_headers, tmp_path, monkeypatch):
    result = await client.post("/api/vault/init", headers=owner_headers, json={"mode": "env", "auto_unseal": True})
    assert result.status_code == 200
    stale_file = tmp_path / "root.key"
    stale_file.write_text(result.json()["root_key"])
    prepared = await prepare_rotation(client, owner_headers)
    assert (await client.post("/api/vault/rotate-root", headers=owner_headers, json=prepared)).status_code == 200
    monkeypatch.setenv("SEKVYR_ROOT_KEY_FILE", str(stale_file))
    config.get_settings.cache_clear()
    messages = []

    async def notify(_session, message):
        messages.append(message)

    monkeypatch.setattr(alerts, "notify", notify)
    await _restart_and_check_root(None)
    assert len(messages) == 1 and "ЗАПЕРТОЙ" in messages[0]


@pytest.mark.parametrize("forget", [False, True])
async def test_rotation_key_file_recovers_or_forgets_after_failed_rename(
    client, owner_headers, env_id, remembered_key, monkeypatch, forget
):
    staged = sealbox.staged_key_file(remembered_key)
    original = remembered_key.read_text()
    real_replace = sealbox.replace_key_file

    def fail_promotion(source, destination):
        if source == staged and destination == remembered_key:
            raise PermissionError("simulated rename failure")
        real_replace(source, destination)

    if not forget:
        wrote = await client.put(f"/api/environments/{env_id}/secrets", headers=owner_headers,
                                 json={"name": "CHECK", "value": "first\nsecond"})
        assert wrote.status_code == 200
        factory = client._transport.app.state.session_factory
        async with factory() as session:
            await session.execute(update(SecretVersion).values(multiline=False))
            await session.commit()

    with monkeypatch.context() as patch:
        patch.setattr(sealbox, "replace_key_file", fail_promotion)
        rotated = await client.post("/api/vault/rotate-root", headers=owner_headers)
        assert rotated.status_code == 200
        assert remembered_key.read_text() == original
        fresh = rotated.json()["root_key"]
        assert staged.read_text() == fresh
        state = (await client.get("/api/vault/status", headers=owner_headers)).json()
        assert state["root_key_configured"] is True
        if not forget:
            # CLI использует валидную копию без изменения файлов ключа.
            assert await _mark_multiline() == 0
            async with factory() as session:
                assert await session.scalar(select(SecretVersion.multiline)) is True
            assert remembered_key.read_text() == original
            assert staged.exists()
            # Автозапуск берет проверенную копию даже пока замена невозможна.
            await _restart_and_check_root(sealbox.unb64(fresh))

    if forget:
        result = await client.post("/api/vault/forget-key", headers=owner_headers)
        assert result.status_code == 200 and not result.json()["present"]
        assert not remembered_key.exists()
        await _restart_and_check_root(None)
    else:
        await _restart_and_check_root(sealbox.unb64(fresh))
        assert remembered_key.read_text() == fresh
    assert not staged.exists()


@pytest.mark.parametrize("unreadable", [False, True])
async def test_remember_current_key_with_bad_staged_copy(
    client, owner_headers, remembered_key, monkeypatch, unreadable
):
    staged = sealbox.staged_key_file(remembered_key)
    staged.write_bytes(b"\xff")
    original = remembered_key.read_text()
    real_read = Path.read_text

    def deny_staged_read(path, *args, **kwargs):
        if path == staged:
            raise PermissionError("simulated read failure")
        return real_read(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        if unreadable:
            patch.setattr(Path, "read_text", deny_staged_read)
        remembered = await client.post("/api/vault/remember-key", headers=owner_headers)
        assert remembered.status_code == 200 and remembered.json()["present"]
    assert remembered_key.read_text() == original
    assert not staged.exists()


@pytest.mark.parametrize("committed", [False, True])
async def test_rotation_resolves_failed_commit_against_db(
    client, owner_headers, remembered_key, monkeypatch, committed
):
    original = remembered_key.read_text()
    real_commit = AsyncSession.commit

    async def fail_commit(session):
        if committed:
            await real_commit(session)
        raise RuntimeError("simulated commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(AsyncSession, "commit", fail_commit)
        if committed:
            result = await client.post("/api/vault/rotate-root", headers=owner_headers)
            assert result.status_code == 200
            assert remembered_key.read_text() == result.json()["root_key"]
            assert remembered_key.read_text() != original
        else:
            with pytest.raises(RuntimeError, match="simulated commit failure"):
                await client.post("/api/vault/rotate-root", headers=owner_headers)
            assert remembered_key.read_text() == original

    state = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert state["root_generation"] == (2 if committed else 1)
    assert not state["sealed"]
    assert not sealbox.staged_key_file(remembered_key).exists()
    await _restart_and_check_root(sealbox.unb64(remembered_key.read_text()))


async def test_rotation_keeps_reads_working_across_commit_and_request_cancellation(
    client, owner_headers, env_id, remembered_key, monkeypatch
):
    base = f"/api/environments/{env_id}"
    wrote = await client.put(base + "/secrets", headers=owner_headers,
                             json={"name": "CHECK", "value": "synthetic-value"})
    assert wrote.status_code == 200
    original = remembered_key.read_text()
    committing, allow_commit = asyncio.Event(), asyncio.Event()
    committed, finish_commit = asyncio.Event(), asyncio.Event()
    real_commit = AsyncSession.commit

    async def pause_rotation(session):
        if committing.is_set():
            await real_commit(session)
            return
        committing.set()
        await allow_commit.wait()
        await real_commit(session)
        committed.set()
        await finish_commit.wait()

    async def check_read():
        value = await client.get(base + "/secret", headers=owner_headers, params={"name": "CHECK"})
        assert value.status_code == 200
        assert value.json()["value"] == "synthetic-value"

    monkeypatch.setattr(AsyncSession, "commit", pause_rotation)
    rotation = asyncio.create_task(client.post("/api/vault/rotate-root", headers=owner_headers))
    try:
        await asyncio.wait_for(committing.wait(), timeout=5)
        # GET пишет журнал. До коммита ротации журнал под блокировкой, поэтому
        # здесь проверяем то же чтение напрямую, без записи в журнал.
        app = client._transport.app
        async with app.state.session_factory() as session:
            secret = await secrets_store.get_secret(session, env_id, "/", "CHECK")
            value = await secrets_store.read_value(session, app.state.sealbox, secret)
        assert value == "synthetic-value"
        rotation.cancel()
        await asyncio.sleep(0)
        assert not rotation.done()
        allow_commit.set()
        await asyncio.wait_for(committed.wait(), timeout=5)
        await check_read()
        assert (await client.post("/api/vault/seal", headers=owner_headers)).json()["sealed"]
    finally:
        allow_commit.set()
        finish_commit.set()
        outcome, = await asyncio.gather(rotation, return_exceptions=True)

    assert isinstance(outcome, asyncio.CancelledError)
    assert remembered_key.read_text() != original
    assert not sealbox.staged_key_file(remembered_key).exists()
    assert (await client.get("/api/vault/status", headers=owner_headers)).json()["sealed"]
    opened = await client.post("/api/vault/unseal", headers=owner_headers,
                               json={"root_key": remembered_key.read_text()})
    assert opened.status_code == 200 and not opened.json()["sealed"]
    await check_read()
    await _restart_and_check_root(sealbox.unb64(remembered_key.read_text()))
