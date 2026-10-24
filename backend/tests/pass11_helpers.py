"""Общие помощники тестов 1.0.1 (test_pass11_*): учетки, права, порог, правки.

Не тестовый модуль: pytest его не собирает, его импортируют тесты."""

from app import alerts

PASS = "member-pass-2026"


async def _user(client, oh, name, role) -> int:
    res = await client.post(
        "/api/users", headers=oh, json={"username": name, "password": PASS, "role": role}
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def _policy(client, oh, **body) -> dict:
    body.setdefault("path_prefix", "/")
    body.setdefault("effect", "allow")
    res = await client.post("/api/policies", headers=oh, json=body)
    assert res.status_code == 201, res.text
    return res.json()


async def _project_id(client, oh) -> int:
    return (await client.get("/api/projects", headers=oh)).json()[0]["id"]


async def _threshold(client, oh, level):
    pid = await _project_id(client, oh)
    res = await client.patch(f"/api/projects/{pid}", headers=oh, json={"approval_min_level": level})
    assert res.status_code == 200, res.text


async def _put(client, h, env, name, value, path="/"):
    return await client.put(
        f"/api/environments/{env}/secrets",
        headers=h,
        json={"name": name, "value": value, "path": path},
    )


async def _values(client, h, env) -> dict:
    res = await client.get(f"/api/environments/{env}/values", headers=h)
    assert res.status_code == 200, res.text
    return {(r["path"], r["name"]): r["value"] for r in res.json()}


async def _approve(client, h, env, name, version):
    return await client.post(
        f"/api/environments/{env}/secret/approve",
        headers=h,
        json={"name": name, "path": "/", "version": version},
    )


def _factory(client):
    return client._transport.app.state.session_factory  # noqa: SLF001


def _capture_alerts(monkeypatch) -> list[str]:
    sent: list[str] = []

    async def fake_notify(session, text):
        sent.append(text)

    monkeypatch.setattr(alerts, "notify", fake_notify)
    return sent
