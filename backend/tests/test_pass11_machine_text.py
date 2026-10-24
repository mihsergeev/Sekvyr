"""Машинный контур: невидимые символы в журнале и списке серверов.

Имя хоста и идентификатор приходят до проверки токена, отчет - от самой
машины. Переворот строки и символы нулевой ширины делали строку журнала
похожей на другую, перевод строки рисовал лишнюю запись.
"""

import base64


TRICKY = "web\u202e1gpj.exe\r\nforged\x00\u200b"


async def _audit(client, oh, action: str) -> list[dict]:
    entries = (await client.get("/api/audit", headers=oh)).json()["entries"]
    return [e for e in entries if e["action"] == action]


async def test_enroll_refusal_logs_hostname_without_invisibles(client, owner_headers):
    res = await client.post(
        "/api/v1/machine/enroll", json={"token": "no-such-token", "hostname": TRICKY}
    )
    assert res.status_code == 401
    entry = (await _audit(client, owner_headers, "machine_enroll_denied"))[0]
    assert entry["target"] == "web1gpj.exeforged"


async def test_enrolled_machine_name_without_invisibles(client, owner_headers, env_id):
    pass_ = (
        await client.post(
            "/api/machines/enroll-token",
            headers=owner_headers,
            json={"environment_id": env_id, "allow_ips": "", "minutes": 15},
        )
    ).json()
    res = await client.post(
        "/api/v1/machine/enroll",
        json={"token": pass_["token"], "hostname": TRICKY, "agent_version": "1.0\u202e"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["name"] == "web1gpj.exeforged"
    entry = (await _audit(client, owner_headers, "machine_enrolled"))[0]
    assert entry["target"] == "web1gpj.exeforged"

    # Имя из одних невидимых - как пустое: машину называет ее идентификатор.
    pass_ = (
        await client.post(
            "/api/machines/enroll-token",
            headers=owner_headers,
            json={"environment_id": env_id, "allow_ips": "", "minutes": 15},
        )
    ).json()
    res = await client.post(
        "/api/v1/machine/enroll", json={"token": pass_["token"], "hostname": "\u202e\u200b\n"}
    )
    assert res.json()["name"] == res.json()["client_id"]


async def test_unknown_client_id_is_logged_without_invisibles(client, owner_headers):
    res = await client.post(
        "/api/v1/machine/token", json={"client_id": TRICKY, "client_secret": "x"}
    )
    assert res.status_code == 401
    entry = (await _audit(client, owner_headers, "machine_denied"))[0]
    assert entry["actor"] == "machine:web1gpj.exeforged"


async def test_basic_pair_is_logged_without_invisibles(client, owner_headers):
    pair = base64.b64encode(f"{TRICKY}:x".encode()).decode()
    res = await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": "Basic " + pair},
        params={"project": "billing", "env": "prod"},
    )
    assert res.status_code == 401
    entry = (await _audit(client, owner_headers, "machine_denied"))[0]
    assert entry["actor"] == "machine:web1gpj.exeforged"


async def test_report_is_stored_without_invisibles(client, owner_headers):
    made = await client.post(
        "/api/machines",
        headers=owner_headers,
        json={"name": "box", "description": "", "allow_ips": "", "expires_at": ""},
    )
    machine = made.json()
    token = (
        await client.post(
            "/api/v1/machine/token",
            json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
        )
    ).json()["access_token"]
    res = await client.post(
        "/api/v1/machine/report",
        headers={"Authorization": "Bearer " + token},
        json={
            "agent_version": "1.0.1\u202e",
            "applied": "billing/prod\nv4\u200b",
            "os": "Ubuntu\u2066 24.04",
            "local_ip": "10.0.0.1\x00",
        },
    )
    assert res.status_code == 200, res.text
    row = next(
        m for m in (await client.get("/api/machines", headers=owner_headers)).json()
        if m["id"] == machine["id"]
    )
    assert (row["agent_version"], row["applied"], row["os"], row["local_ip"]) == (
        "1.0.1", "billing/prodv4", "Ubuntu 24.04", "10.0.0.1",
    )
    entry = (await _audit(client, owner_headers, "machine_reported"))[0]
    assert entry["detail"] == "1.0.1 billing/prodv4"
