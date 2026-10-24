"""Недельная сводка правок (1.0.1).

Падает на 1.0.0: подтверждение, перенос, восстановление снимка и смена
родителя в сводку не попадали, а голое предложение правки считалось.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from app import alerts, fleet_watch, importers, settings_store
from app.models import AuditLog
from tests.conftest import login
from tests.pass11_helpers import (
    PASS,
    _approve,
    _factory,
    _policy,
    _project_id,
    _put,
    _threshold,
    _user,
)

# --- 5. недельная сводка ----------------------------------------------------


async def _last_week_done(client):
    async with _factory(client)() as s:
        await s.execute(
            update(AuditLog).values(ts=datetime.now(timezone.utc) - timedelta(days=30))
        )
        await settings_store.put(
            s, fleet_watch.DIGEST_KEY,
            (datetime.now(timezone.utc) - timedelta(days=8)).isoformat(),
        )
        await s.commit()


def _capture_digest(monkeypatch) -> list[str]:
    sent: list[str] = []

    async def fake_later(sf, text):
        sent.append(text)
        return True

    monkeypatch.setattr(alerts, "notify_later", fake_later)
    return sent


async def test_weekly_digest_counts_approved_migrated_restored(client, owner_headers, env_id, monkeypatch):
    oh = owner_headers
    pid = await _project_id(client, oh)
    assert (await _put(client, oh, env_id, "A", "1")).status_code == 200
    snap = await client.post(f"/api/environments/{env_id}/snapshots", headers=oh, json={"name": "s1"})
    assert snap.status_code == 201, snap.text
    assert (await _put(client, oh, env_id, "A", "2")).status_code == 200
    await _threshold(client, oh, 30)
    did = await _user(client, oh, "dev", "developer")
    await _policy(
        client, oh, subject_type="user", subject_id=did, project_id=pid,
        actions=["list", "read", "write"],
    )
    dev = await login(client, "dev", PASS)
    proposal = await _put(client, dev, env_id, "B", "x")
    await _last_week_done(client)

    assert (await _approve(client, oh, env_id, "B", proposal.json()["version"])).status_code == 200
    await _threshold(client, oh, 0)
    restored = await client.post(
        f"/api/environments/{env_id}/snapshots/{snap.json()['id']}/restore", headers=oh
    )
    assert restored.status_code == 200, restored.text

    async def fake_fetch(url, token, *, mount, path=""):
        return importers.Fetched(items=[importers.Item(path="/", name="M1", value="v")])

    monkeypatch.setattr(importers, "vault_fetch", fake_fetch)
    res = await client.post(
        "/api/migrate/apply", headers=oh,
        json={"source": "vault", "url": "http://10.0.0.5:8200", "token": "t", "environment_id": env_id},
    )
    assert res.status_code == 200, res.text
    staging = await client.post(f"/api/projects/{pid}/environments", headers=oh, json={"name": "staging"})
    res = await client.patch(
        f"/api/environments/{env_id}", headers=oh, json={"parent_id": staging.json()["id"]}
    )
    assert res.status_code == 200, res.text

    sent = _capture_digest(monkeypatch)
    assert await fleet_watch.sweep_digest(_factory(client)) is True
    assert sent and "за неделю правок значений — 4" in sent[0], sent


async def test_weekly_digest_ignores_bare_proposals(client, owner_headers, env_id, monkeypatch):
    oh = owner_headers
    pid = await _project_id(client, oh)
    await _threshold(client, oh, 30)
    did = await _user(client, oh, "dev", "developer")
    await _policy(
        client, oh, subject_type="user", subject_id=did, project_id=pid,
        actions=["list", "read", "write"],
    )
    await _last_week_done(client)
    dev = await login(client, "dev", PASS)
    assert (await _put(client, dev, env_id, "B", "x")).json()["pending"] is True

    sent = _capture_digest(monkeypatch)
    assert await fleet_watch.sweep_digest(_factory(client)) is False
    assert sent == []
