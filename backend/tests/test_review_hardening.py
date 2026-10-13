"""Подтверждение правок, откат и снимки: то, что обходило порог или роняло 500.

Найдено разбором перед выпуском 1.0.0: откат выпускал правку в обход
подтверждения, подтверждение применяло устаревшую правку, снимки не понимали
наследования и переименований.
"""

import httpx

from tests.conftest import login
from tests.test_approval import PASS, _grant, _set_threshold, _user


async def _put(client, headers, env_id, name, value, path="/"):
    return await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=headers,
        json={"name": name, "value": value, "path": path},
    )


async def _value(client, headers, env_id, name, path="/"):
    res = await client.get(
        f"/api/environments/{env_id}/secret", headers=headers, params={"name": name, "path": path}
    )
    return res.json().get("value") if res.status_code == 200 else res.status_code


async def _dev(client, owner_headers) -> dict[str, str]:
    """Разработчик с правом читать и писать, порог проекта - ответственный."""
    await _set_threshold(client, owner_headers, 30)
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _grant(client, owner_headers, dev_id, ["list", "read", "write", "delete"])
    return await login(client, "dev", PASS)


async def _versions(client, headers, env_id, name):
    res = await client.get(
        f"/api/environments/{env_id}/secret/history", headers=headers, params={"name": name}
    )
    return res.json()


async def test_rollback_cannot_release_an_unreviewed_edit(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Откат к своей ожидающей или отклоненной правке выпускал ее в прод."""
    await _put(client, owner_headers, env_id, "TOKEN", "reviewed")
    dev = await _dev(client, owner_headers)
    proposal = await _put(client, dev, env_id, "TOKEN", "unreviewed")
    pending_no = proposal.json()["version"]

    res = await client.post(
        f"/api/environments/{env_id}/secret/rollback",
        headers=dev,
        json={"name": "TOKEN", "version": pending_no},
    )
    assert res.status_code == 400, res.text
    assert await _value(client, owner_headers, env_id, "TOKEN") == "reviewed"

    rejected = await client.post(
        f"/api/environments/{env_id}/secret/reject",
        headers=owner_headers,
        json={"name": "TOKEN", "version": pending_no, "note": "нет"},
    )
    assert rejected.status_code == 204, rejected.text
    res = await client.post(
        f"/api/environments/{env_id}/secret/rollback",
        headers=dev,
        json={"name": "TOKEN", "version": pending_no},
    )
    assert res.status_code == 400
    assert await _value(client, owner_headers, env_id, "TOKEN") == "reviewed"


async def test_rollback_below_threshold_waits_for_approval(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "KEY", "first")
    await _put(client, owner_headers, env_id, "KEY", "second")
    dev = await _dev(client, owner_headers)
    res = await client.post(
        f"/api/environments/{env_id}/secret/rollback", headers=dev, json={"name": "KEY", "version": 1}
    )
    assert res.status_code == 200, res.text
    assert await _value(client, owner_headers, env_id, "KEY") == "second"
    pending = (await client.get(f"/api/environments/{env_id}/pending", headers=owner_headers)).json()
    assert [p["name"] for p in pending] == ["KEY"]


async def test_direct_actions_below_threshold_are_refused(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Удаление, переименование, импорт, возврат к родителю и снимок не умеют
    ждать подтверждения - ниже порога им отказ, а не изменение в обход."""
    await _put(client, owner_headers, env_id, "KEY", "value")
    snap = await client.post(
        f"/api/environments/{env_id}/snapshots", headers=owner_headers, json={"name": "s1"}
    )
    dev = await _dev(client, owner_headers)
    base = f"/api/environments/{env_id}"
    attempts = [
        client.delete(f"{base}/secret", headers=dev, params={"name": "KEY"}),
        client.post(f"{base}/secret/rename", headers=dev, json={"name": "KEY", "new_name": "KEY2"}),
        client.post(f"{base}/import", headers=dev, json={"text": "KEY=evil\n", "overwrite": True}),
        client.post(f"{base}/secret/inherit", headers=dev, json={"name": "KEY"}),
        client.post(f"{base}/snapshots/{snap.json()['id']}/restore", headers=dev),
    ]
    for attempt in attempts:
        res = await attempt
        assert res.status_code == 403, res.text
    assert await _value(client, owner_headers, env_id, "KEY") == "value"


async def test_stale_proposal_does_not_overwrite_a_hotfix(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "KEY", "v1")
    dev = await _dev(client, owner_headers)
    proposal = (await _put(client, dev, env_id, "KEY", "dev-v2")).json()["version"]
    await _put(client, owner_headers, env_id, "KEY", "hotfix")
    res = await client.post(
        f"{'/api/environments/'}{env_id}/secret/approve",
        headers=owner_headers,
        json={"name": "KEY", "version": proposal},
    )
    assert res.status_code == 404, res.text
    assert await _value(client, owner_headers, env_id, "KEY") == "hotfix"
    history = await _versions(client, owner_headers, env_id, "KEY")
    stale = next(v for v in history if v["version"] == proposal)
    assert stale["status"] == "rejected"


async def test_older_proposal_after_a_newer_one(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "KEY", "v1")
    dev = await _dev(client, owner_headers)
    first = (await _put(client, dev, env_id, "KEY", "older")).json()["version"]
    second = (await _put(client, dev, env_id, "KEY", "newer")).json()["version"]
    ok = await client.post(
        f"/api/environments/{env_id}/secret/approve",
        headers=owner_headers,
        json={"name": "KEY", "version": second},
    )
    assert ok.status_code == 200, ok.text
    late = await client.post(
        f"/api/environments/{env_id}/secret/approve",
        headers=owner_headers,
        json={"name": "KEY", "version": first},
    )
    assert late.status_code == 404
    assert await _value(client, owner_headers, env_id, "KEY") == "newer"


async def test_rename_retires_proposals(client: httpx.AsyncClient, owner_headers, env_id):
    """Правка к старому имени после переименования висела навсегда или
    откатывала переименование при подтверждении."""
    await _put(client, owner_headers, env_id, "DB_PASS", "v1")
    dev = await _dev(client, owner_headers)
    await _put(client, dev, env_id, "DB_PASS", "dev-v2")
    res = await client.post(
        f"/api/environments/{env_id}/secret/rename",
        headers=owner_headers,
        json={"name": "DB_PASS", "new_name": "DB_PASSWORD"},
    )
    assert res.status_code == 200, res.text
    pending = (await client.get(f"/api/environments/{env_id}/pending", headers=owner_headers)).json()
    assert pending == []
    assert await _value(client, owner_headers, env_id, "DB_PASSWORD") == "v1"


async def _child(client, owner_headers, env_id) -> int:
    project_id = (await client.get("/api/projects", headers=owner_headers)).json()[0]["id"]
    res = await client.post(
        f"/api/projects/{project_id}/environments",
        headers=owner_headers,
        json={"name": "stage", "parent_id": env_id},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _snapshot(client, headers, env, name) -> int:
    res = await client.post(f"/api/environments/{env}/snapshots", headers=headers, json={"name": name})
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _restore(client, headers, env, snap):
    res = await client.post(f"/api/environments/{env}/snapshots/{snap}/restore", headers=headers)
    assert res.status_code == 200, res.text
    return res.json()


async def test_snapshots_understand_inheritance(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "K", "parent")
    child = await _child(client, owner_headers, env_id)
    await _put(client, owner_headers, child, "K", "child")

    # Снимок со своим значением, затем возврат к родителю: снимок возвращает свое.
    own = await _snapshot(client, owner_headers, child, "own")
    await client.post(f"/api/environments/{child}/secret/inherit", headers=owner_headers, json={"name": "K"})
    assert await _value(client, owner_headers, child, "K") == "parent"
    await _restore(client, owner_headers, child, own)
    assert await _value(client, owner_headers, child, "K") == "child"

    # Снимок в состоянии "брать у родителя": восстановление снова отдает родителю,
    # а не падает на версии без шифротекста.
    await client.post(f"/api/environments/{child}/secret/inherit", headers=owner_headers, json={"name": "K"})
    inherit = await _snapshot(client, owner_headers, child, "inherit")
    await _put(client, owner_headers, child, "K", "override")
    plan = (await client.get(f"/api/environments/{child}/snapshots/{inherit}/plan", headers=owner_headers)).json()
    assert [row["action"] for row in plan] == ["вернуть к наследованию"]
    await _restore(client, owner_headers, child, inherit)
    assert await _value(client, owner_headers, child, "K") == "parent"

    # Удаление в дочернем окружении прячет значение родителя - и снимок это помнит.
    await _put(client, owner_headers, child, "K", "to-delete")
    await client.delete(f"/api/environments/{child}/secret", headers=owner_headers, params={"name": "K"})
    hidden = await _snapshot(client, owner_headers, child, "hidden")
    await client.post(f"/api/environments/{child}/secret/inherit", headers=owner_headers, json={"name": "K"})
    assert await _value(client, owner_headers, child, "K") == "parent"
    await _restore(client, owner_headers, child, hidden)
    assert await _value(client, owner_headers, child, "K") == 404


async def test_snapshot_after_rename_and_reuse_of_the_name(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "A", "one")
    snap = await _snapshot(client, owner_headers, env_id, "before")
    await client.post(
        f"/api/environments/{env_id}/secret/rename",
        headers=owner_headers,
        json={"name": "A", "new_name": "B"},
    )
    await _put(client, owner_headers, env_id, "A", "two")
    result = await _restore(client, owner_headers, env_id, snap)
    assert result["removed"] == 1
    assert await _value(client, owner_headers, env_id, "B") == "one"
    assert await _value(client, owner_headers, env_id, "A") == 404


async def test_no_current_value_is_404_not_500(client: httpx.AsyncClient, owner_headers, env_id):
    await _put(client, owner_headers, env_id, "GONE", "x")
    await client.delete(f"/api/environments/{env_id}/secret", headers=owner_headers, params={"name": "GONE"})
    base = f"/api/environments/{env_id}"
    rename = await client.post(f"{base}/secret/rename", headers=owner_headers, json={"name": "GONE", "new_name": "STILL_GONE"})
    assert rename.status_code in (404, 409), rename.text
    same = await client.get(f"{base}/same", headers=owner_headers, params={"name": "GONE"})
    assert same.status_code == 404, same.text

    child = await _child(client, owner_headers, env_id)
    await _put(client, owner_headers, env_id, "K", "parent")
    await _put(client, owner_headers, child, "K", "child")
    await client.post(f"/api/environments/{child}/secret/inherit", headers=owner_headers, json={"name": "K"})
    history = await _versions(client, owner_headers, child, "K")
    inherits = history[0]["version"]
    res = await client.get(
        f"/api/environments/{child}/secret/version", headers=owner_headers, params={"name": "K", "version": inherits}
    )
    assert res.status_code == 404, res.text
    back = await client.post(
        f"/api/environments/{child}/secret/rollback", headers=owner_headers, json={"name": "K", "version": inherits}
    )
    assert back.status_code in (400, 404), back.text

    spread = await client.post(
        f"/api/environments/{env_id}/spread",
        headers=owner_headers,
        json={"name": "K", "path": "/", "targets": [child]},
    )
    assert spread.status_code == 200, spread.text
    assert await _value(client, owner_headers, child, "K") == "parent"
