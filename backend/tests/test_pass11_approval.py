"""Кто подтверждает и что бывает с правками ушедших (1.0.1).

Падает на 1.0.0: ответственный подтверждал правку своей марионетки через сброс
ее пароля, уровень автора брался на момент подтверждения, правки отключенных и
пониженных висели, а ответственный включал учетку, которую отключил владелец.
"""

from sqlalchemy import select, update

from app.models import AuditLog, User
from tests.conftest import login
from tests.pass11_helpers import (
    PASS,
    _approve,
    _capture_alerts,
    _factory,
    _policy,
    _project_id,
    _put,
    _threshold,
    _user,
    _values,
)


# --- 2. самоподтверждение и родня ------------------------------------------


async def test_reviewer_below_threshold_cannot_approve_puppet(client, owner_headers, env_id, monkeypatch):
    """Порог - владелец. Ответственный задает пароль разработчику, предлагает от
    его имени и пробует подтвердить сам: подтверждать может только роль не ниже
    порога, а сброс пароля уходит оповещением."""
    sent = _capture_alerts(monkeypatch)
    oh = owner_headers
    pid = await _project_id(client, oh)
    assert (await _put(client, oh, env_id, "DB_PASSWORD", "real")).status_code == 200
    await _threshold(client, oh, 40)
    mid = await _user(client, oh, "lead", "maintainer")
    did = await _user(client, oh, "dev", "developer")
    await _policy(
        client, oh, subject_type="user", subject_id=mid, project_id=pid,
        actions=["list", "read", "write", "approve"],
    )
    await _policy(
        client, oh, subject_type="user", subject_id=did, project_id=pid,
        actions=["list", "read", "write"],
    )
    lead = await login(client, "lead", PASS)
    sent.clear()
    res = await client.post(
        f"/api/users/{did}/password", headers=lead, json={"new_password": "puppet-password-2026"}
    )
    assert res.status_code == 204, res.text
    assert sent == ["Sekvyr: lead задал пароль учетной записи dev"]

    puppet = await login(client, "dev", "puppet-password-2026")
    proposal = await _put(client, puppet, env_id, "DB_PASSWORD", "lead-wants-this")
    assert proposal.json()["pending"] is True
    res = await _approve(client, lead, env_id, "DB_PASSWORD", proposal.json()["version"])
    assert res.status_code == 403, res.text
    assert res.json()["detail"] == "Подтвердить правку может только роль не ниже порога проекта"
    assert (await _values(client, oh, env_id))[("/", "DB_PASSWORD")] == "real"

    # Отклонить ответственный может: отказ значений не меняет.
    res = await client.post(
        f"/api/environments/{env_id}/secret/reject",
        headers=lead,
        json={"name": "DB_PASSWORD", "path": "/", "version": proposal.json()["version"], "note": "нет"},
    )
    assert res.status_code == 204, res.text


async def test_author_level_is_fixed_at_proposal(client, owner_headers, env_id):
    """Уровень автора записан в версии: если роль автора сменят в обход
    маршрута учеток, правку ответственного все так же подтверждает только тот,
    кто выше ответственного."""
    oh = owner_headers
    pid = await _project_id(client, oh)
    assert (await _put(client, oh, env_id, "TOKEN", "real")).status_code == 200
    await _threshold(client, oh, 30)
    a = await _user(client, oh, "alead", "maintainer")
    b = await _user(client, oh, "blead", "maintainer")
    await _policy(
        client, oh, subject_type="user", subject_id=a, project_id=pid,
        actions=["list", "read", "write"],
    )
    await _policy(
        client, oh, subject_type="user", subject_id=b, project_id=pid,
        actions=["list", "read", "approve"],
    )
    await _threshold(client, oh, 40)
    ah = await login(client, "alead", PASS)
    proposal = await _put(client, ah, env_id, "TOKEN", "from-a")
    assert proposal.json()["pending"] is True
    await _threshold(client, oh, 30)

    async with _factory(client)() as s:
        await s.execute(update(User).where(User.id == a).values(role="developer"))
        await s.commit()
    bh = await login(client, "blead", PASS)
    res = await _approve(client, bh, env_id, "TOKEN", proposal.json()["version"])
    assert res.status_code == 403, res.text
    assert (await _values(client, oh, env_id))[("/", "TOKEN")] == "real"


async def test_role_change_withdraws_pending(client, owner_headers, env_id):
    oh = owner_headers
    pid = await _project_id(client, oh)
    assert (await _put(client, oh, env_id, "TOKEN", "real")).status_code == 200
    await _threshold(client, oh, 40)
    a = await _user(client, oh, "alead", "maintainer")
    b = await _user(client, oh, "blead", "maintainer")
    await _policy(
        client, oh, subject_type="user", subject_id=a, project_id=pid,
        actions=["list", "read", "write"],
    )
    await _policy(
        client, oh, subject_type="user", subject_id=b, project_id=pid,
        actions=["list", "read", "approve"],
    )
    ah = await login(client, "alead", PASS)
    proposal = await _put(client, ah, env_id, "TOKEN", "from-a")
    assert proposal.json()["pending"] is True

    res = await client.patch(f"/api/users/{a}", headers=oh, json={"role": "developer"})
    assert res.status_code == 200, res.text
    assert res.json()["proposals_withdrawn"] == 1
    assert (await client.get(f"/api/environments/{env_id}/pending", headers=oh)).json() == []
    await _threshold(client, oh, 30)
    bh = await login(client, "blead", PASS)
    res = await _approve(client, bh, env_id, "TOKEN", proposal.json()["version"])
    assert res.status_code == 404, res.text
    assert (await _values(client, oh, env_id))[("/", "TOKEN")] == "real"


async def test_disabling_author_withdraws_pending_with_audit(client, owner_headers, env_id):
    oh = owner_headers
    pid = await _project_id(client, oh)
    assert (await _put(client, oh, env_id, "API_KEY", "real")).status_code == 200
    await _threshold(client, oh, 30)
    did = await _user(client, oh, "dev", "developer")
    await _policy(
        client, oh, subject_type="user", subject_id=did, project_id=pid,
        actions=["list", "read", "write"],
    )
    dev = await login(client, "dev", PASS)
    proposal = await _put(client, dev, env_id, "API_KEY", "from-fired-dev")
    assert proposal.json()["pending"] is True

    res = await client.patch(f"/api/users/{did}", headers=oh, json={"disabled": True})
    assert res.status_code == 200, res.text
    assert res.json()["proposals_withdrawn"] == 1
    assert (await client.get(f"/api/environments/{env_id}/pending", headers=oh)).json() == []
    res = await _approve(client, oh, env_id, "API_KEY", proposal.json()["version"])
    assert res.status_code == 404
    async with _factory(client)() as s:
        rows = list(await s.scalars(select(AuditLog).where(AuditLog.action == "secret_rejected")))
    assert [(r.actor, r.detail) for r in rows] == [
        ("owner", f"версия {proposal.json()['version']}, автор dev: автора отключили")
    ]


async def test_maintainer_cannot_enable_account_owner_disabled(client, owner_headers):
    oh = owner_headers
    await _user(client, oh, "lead", "maintainer")
    by_owner = await _user(client, oh, "dev1", "developer")
    by_lead = await _user(client, oh, "dev2", "developer")
    lead = await login(client, "lead", PASS)
    assert (await client.patch(f"/api/users/{by_owner}", headers=oh, json={"disabled": True})).status_code == 200
    assert (await client.patch(f"/api/users/{by_lead}", headers=lead, json={"disabled": True})).status_code == 200

    res = await client.patch(f"/api/users/{by_owner}", headers=lead, json={"disabled": False})
    assert res.status_code == 403, res.text
    assert res.json()["detail"].startswith("Эту учетную запись отключила роль выше вашей")
    res = await client.patch(f"/api/users/{by_lead}", headers=lead, json={"disabled": False})
    assert res.status_code == 200, res.text
    res = await client.patch(f"/api/users/{by_owner}", headers=oh, json={"disabled": False})
    assert res.status_code == 200, res.text


async def test_account_disabled_before_upgrade_counts_as_owner_disabled(client, owner_headers):
    oh = owner_headers
    await _user(client, oh, "lead", "maintainer")
    did = await _user(client, oh, "dev", "developer")
    async with _factory(client)() as s:
        await s.execute(update(User).where(User.id == did).values(disabled=True, disabled_by_level=None))
        await s.commit()
    lead = await login(client, "lead", PASS)
    res = await client.patch(f"/api/users/{did}", headers=lead, json={"disabled": False})
    assert res.status_code == 403, res.text
