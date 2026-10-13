"""Машинный контур: сервер забирает свое и не может ничего испортить."""

import httpx

from app import machines, ratelimit
from tests.conftest import login


async def _machine(client, owner_headers, **extra) -> dict:
    body = {"name": "ci-runner", "description": "", "allow_ips": "", "expires_at": ""}
    body.update(extra)
    res = await client.post("/api/machines", headers=owner_headers, json=body)
    assert res.status_code == 201, res.text
    return res.json()


async def _grant(client, owner_headers, machine_id: int, env_id: int, actions=("read",)):
    res = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "machine",
            "subject_id": machine_id,
            "environment_id": env_id,
            "path_prefix": "/",
            "actions": list(actions),
            "effect": "allow",
        },
    )
    return res


async def _token(client, machine: dict) -> str:
    res = await client.post(
        "/api/v1/machine/token",
        json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


async def test_machine_reads_its_environment(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": "секрет"},
    )
    machine = await _machine(client, owner_headers)
    assert (await _grant(client, owner_headers, machine["id"], env_id)).status_code == 201

    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    res = await client.get(
        "/api/v1/machine/secrets", headers=headers, params={"project": "billing", "env": "prod"}
    )
    assert res.status_code == 200, res.text
    values = {row["name"]: row["value"] for row in res.json()["values"]}
    assert values["DB_PASSWORD"] == "секрет"

    # тот же набор готовым файлом
    text = (
        await client.get(
            "/api/v1/machine/env", headers=headers, params={"project": "billing", "env": "prod"}
        )
    ).json()["text"]
    assert "DB_PASSWORD=" in text


async def test_machine_without_policy_gets_nothing(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Закрыто по умолчанию: заведенная машина не видит ничего, пока ей не выдали."""
    machine = await _machine(client, owner_headers)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    res = await client.get(
        "/api/v1/machine/secrets", headers=headers, params={"project": "billing", "env": "prod"}
    )
    assert res.status_code == 403


async def test_machine_cannot_be_granted_write(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Право на запись машине не выдается: выполнять его в машинном контуре
    некому, маршрутов нет вовсе."""
    machine = await _machine(client, owner_headers)
    res = await _grant(client, owner_headers, machine["id"], env_id, actions=("read", "write"))
    assert res.status_code == 400
    assert "чтение" in res.json()["detail"]


async def test_machine_contour_has_no_writing_routes(client: httpx.AsyncClient):
    """Свойство конструкции, а не настройка: писать в секреты машине некуда."""
    from app.api import machine as machine_api

    writing = {
        (method, route.path)
        for route in machine_api.router.routes
        for method in getattr(route, "methods", set())
        if method in {"POST", "PUT", "PATCH", "DELETE"}
    }
    assert {path for _m, path in writing} == {
        "/v1/machine/token",
        "/v1/machine/report",
        "/v1/machine/revoke",
        # Подключение сервера: заводит машинную личность по одноразовому
        # токену - значений не касается.
        "/v1/machine/enroll",
    }


async def test_disabled_machine_loses_access_at_once(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Выключение действует сразу, а не через четверть часа, когда истечет
    уже выданный токен."""
    machine = await _machine(client, owner_headers)
    await _grant(client, owner_headers, machine["id"], env_id)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    assert (
        await client.get(
            "/api/v1/machine/secrets", headers=headers, params={"project": "billing", "env": "prod"}
        )
    ).status_code == 200

    await client.patch(
        f"/api/machines/{machine['id']}", headers=owner_headers, json={"disabled": True}
    )
    res = await client.get(
        "/api/v1/machine/secrets", headers=headers, params={"project": "billing", "env": "prod"}
    )
    assert res.status_code == 401


async def test_rotating_the_secret_kills_old_tokens(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    machine = await _machine(client, owner_headers)
    await _grant(client, owner_headers, machine["id"], env_id)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}

    fresh = await client.post(f"/api/machines/{machine['id']}/secret", headers=owner_headers)
    assert fresh.status_code == 200
    assert fresh.json()["client_secret"] != machine["client_secret"]

    stale = await client.get(
        "/api/v1/machine/secrets", headers=headers, params={"project": "billing", "env": "prod"}
    )
    assert stale.status_code == 401


async def test_machine_reports_itself(client: httpx.AsyncClient, owner_headers, env_id):
    machine = await _machine(client, owner_headers)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    res = await client.post(
        "/api/v1/machine/report",
        headers=headers,
        json={"agent_version": "0.1.0", "applied": "billing/prod v4"},
    )
    assert res.status_code == 200

    listed = (await client.get("/api/machines", headers=owner_headers)).json()
    row = [m for m in listed if m["id"] == machine["id"]][0]
    assert row["agent_version"] == "0.1.0"
    assert row["applied"] == "billing/prod v4"
    assert row["last_seen_at"]


async def test_report_names_the_application_and_its_file(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Панель запоминает, какое приложение сервер забирает и куда кладет файл.

    Ради этого все и затевалось: на странице окружения должно быть видно не
    "кто-то это читает", а какой сервер, в какой файл и когда.
    """
    machine = await _machine(client, owner_headers)
    await _grant(client, owner_headers, machine["id"], env_id)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    res = await client.post(
        "/api/v1/machine/report",
        headers=headers,
        json={
            "agent_version": "0.24.2",
            "applied": "ключей 7",
            "project": "billing",
            "env": "prod",
            "path": "/run/sekvyr/billing.env",
        },
    )
    assert res.status_code == 200

    listed = (await client.get("/api/machines", headers=owner_headers)).json()
    row = [m for m in listed if m["id"] == machine["id"]][0]
    assert row["apps"] == [
        {
            "environment": "billing/prod",
            "path": "/run/sekvyr/billing.env",
            "applied": "ключей 7",
            "last_seen_at": row["apps"][0]["last_seen_at"],
        }
    ]
    assert row["apps"][0]["last_seen_at"]


async def test_report_about_a_foreign_environment_is_ignored(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Отчет приходит от самой машины, и на слово ей верить незачем.

    Иначе своей же строкой она объявилась бы на странице окружения, к которому
    ей доступ не выдавали.
    """
    machine = await _machine(client, owner_headers)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    res = await client.post(
        "/api/v1/machine/report",
        headers=headers,
        json={"agent_version": "0.24.2", "project": "billing", "env": "prod"},
    )
    assert res.status_code == 200

    listed = (await client.get("/api/machines", headers=owner_headers)).json()
    row = [m for m in listed if m["id"] == machine["id"]][0]
    assert row["apps"] == []


async def test_wrong_secret_is_refused_without_hints(client: httpx.AsyncClient, owner_headers):
    machine = await _machine(client, owner_headers)
    res = await client.post(
        "/api/v1/machine/token",
        json={"client_id": machine["client_id"], "client_secret": "не тот"},
    )
    assert res.status_code == 401
    missing = await client.post(
        "/api/v1/machine/token", json={"client_id": "skv-нет", "client_secret": "любой"}
    )
    # Ответ одинаковый: разница подсказывала бы, какой из двух параметров угадан.
    assert missing.status_code == 401
    assert missing.json()["detail"] == res.json()["detail"]


def test_ip_allowlist_reads_addresses_and_subnets():
    assert machines.ip_allowed("", "203.0.113.7") is True
    assert machines.ip_allowed("203.0.113.7", "203.0.113.7") is True
    assert machines.ip_allowed("203.0.113.0/24", "203.0.113.7") is True
    assert machines.ip_allowed("198.51.100.0/24", "203.0.113.7") is False
    # Опечатка в списке не должна открывать дверь всем.
    assert machines.ip_allowed("не адрес", "203.0.113.7") is False


async def test_ip_outside_the_list_is_refused(client: httpx.AsyncClient, owner_headers):
    machine = await _machine(client, owner_headers, allow_ips="198.51.100.0/24")
    res = await client.post(
        "/api/v1/machine/token",
        json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
    )
    assert res.status_code == 401


async def _enroll_token(client, owner_headers, env_id: int | None = None, minutes: int = 15):
    res = await client.post(
        "/api/machines/enroll-token",
        headers=owner_headers,
        json={"environment_id": env_id, "allow_ips": "", "minutes": minutes},
    )
    assert res.status_code == 200, res.text
    return res.json()


async def test_server_connects_by_one_time_token(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Подключение одной командой: токен меняется на постоянную личность, и
    сервер сразу видит выданное ему окружение."""
    await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_HOST", "value": "pg.internal"},
    )
    pass_ = await _enroll_token(client, owner_headers, env_id)
    assert "install.sh" in pass_["command"] and pass_["token"] in pass_["command"]

    res = await client.post(
        "/api/v1/machine/enroll",
        json={"token": pass_["token"], "hostname": "web-1", "agent_version": "0.1.0"},
    )
    assert res.status_code == 200, res.text
    identity = res.json()
    assert identity["name"] == "web-1"
    assert identity["project"] == "billing" and identity["env"] == "prod"

    token = (
        await client.post(
            "/api/v1/machine/token",
            json={
                "client_id": identity["client_id"],
                "client_secret": identity["client_secret"],
            },
        )
    ).json()["access_token"]
    values = await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": "Bearer " + token},
        params={"project": "billing", "env": "prod"},
    )
    assert values.status_code == 200
    assert [v["name"] for v in values.json()["values"]] == ["DB_HOST"]


async def test_enroll_token_burns_after_the_first_use(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Токен годен ровно на одну регистрацию: переслать его "на всякий
    случай" бесполезно."""
    pass_ = await _enroll_token(client, owner_headers, env_id)
    first = await client.post(
        "/api/v1/machine/enroll", json={"token": pass_["token"], "hostname": "node-1"}
    )
    assert first.status_code == 200
    second = await client.post(
        "/api/v1/machine/enroll", json={"token": pass_["token"], "hostname": "node-2"}
    )
    assert second.status_code == 401


async def test_unknown_enroll_token_is_refused(client: httpx.AsyncClient):
    res = await client.post(
        "/api/v1/machine/enroll", json={"token": "не-настоящий-токен", "hostname": "node"}
    )
    assert res.status_code == 401


async def test_environment_of_a_machine_names_its_group(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """"frontend/prod" без группы подошло бы сразу двум командам, поэтому в
    списке окружений сервера стоит и она."""
    machine = await _machine(client, owner_headers)
    await _grant(client, owner_headers, machine["id"], env_id)
    listed = (await client.get("/api/machines", headers=owner_headers)).json()
    row = [m for m in listed if m["id"] == machine["id"]][0]
    # Проект billing в фикстуре заведен без группы, поэтому префикса нет.
    assert row["environments"] == ["billing/prod"]

    grouped = await client.post(
        "/api/projects",
        headers=owner_headers,
        json={"slug": "front", "title": "", "group_name": "Globex", "environments": []},
    )
    env = await client.post(
        f"/api/projects/{grouped.json()['id']}/environments",
        headers=owner_headers,
        json={"name": "prod"},
    )
    await _grant(client, owner_headers, machine["id"], env.json()["id"])
    listed = (await client.get("/api/machines", headers=owner_headers)).json()
    row = [m for m in listed if m["id"] == machine["id"]][0]
    assert "globex/front/prod" in row["environments"]


async def test_enroll_ticket_has_app_command(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Панель отдает и вторую команду - для сервера, который уже подключен.

    Собирать её руками означает четыре флага и ошибку в группе: так и вышло на
    первой живой проверке.
    """
    res = await client.post(
        "/api/machines/enroll-token", headers=owner_headers, json={"environment_id": env_id}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["command"].startswith("curl -fsSL")
    assert "--token" in body["command"]

    # Для сервера с агентом - одна короткая строка без флагов.
    assert body["app_command"] == "sudo sekvyr add billing/prod"
    # А команда подключения сразу заводит первое приложение: возвращаться в
    # панель второй раз незачем.
    assert "--project billing --env prod" in body["command"]


async def test_attach_grants_and_returns_command(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Одно действие вместо двух: права выданы, команда готова.

    Раньше право выдавали в "Доступе", а команду собирали руками - и забытая
    политика встречала агента отказом "этой машине окружение не выдано".
    """
    machine = await _machine(client, owner_headers)
    res = await client.post(
        f"/api/machines/{machine['id']}/attach",
        headers=owner_headers,
        json={"environment_id": env_id},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["granted"] is True
    assert body["environment"] == "billing/prod"
    assert body["command"] == "sudo sekvyr add billing/prod"

    # Машина сразу читает окружение: политика на месте.
    token = (
        await client.post(
            "/api/v1/machine/token",
            json={"client_id": machine["client_id"], "client_secret": machine["client_secret"]},
        )
    ).json()["access_token"]
    read = await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": f"Bearer {token}"},
        params={"project": "billing", "env": "prod"},
    )
    assert read.status_code == 200, read.text

    # Повторное подключение прав не плодит.
    again = await client.post(
        f"/api/machines/{machine['id']}/attach",
        headers=owner_headers,
        json={"environment_id": env_id},
    )
    assert again.json()["granted"] is False

async def test_report_tells_os_and_local_ip(client: httpx.AsyncClient, owner_headers, env_id):
    """Система и локальный адрес приходят от сервера и держатся в панели.

    Пустое поле не затирает известное: старый агент про систему молчит, и терять
    из-за его отчета то, что панель уже показывала, незачем.
    """
    machine = await _machine(client, owner_headers)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    first = await client.post(
        "/api/v1/machine/report",
        headers=headers,
        json={
            "agent_version": "0.26.0",
            "os": "Ubuntu 24.04.2 LTS",
            "local_ip": "192.168.0.9",
        },
    )
    assert first.status_code == 200

    listed = (await client.get("/api/machines", headers=owner_headers)).json()
    row = [m for m in listed if m["id"] == machine["id"]][0]
    assert row["os"] == "Ubuntu 24.04.2 LTS"
    assert row["local_ip"] == "192.168.0.9"

    old = await client.post(
        "/api/v1/machine/report", headers=headers, json={"agent_version": "0.25.0"}
    )
    assert old.status_code == 200
    listed = (await client.get("/api/machines", headers=owner_headers)).json()
    row = [m for m in listed if m["id"] == machine["id"]][0]
    assert row["os"] == "Ubuntu 24.04.2 LTS"
    assert row["local_ip"] == "192.168.0.9"


def test_country_comes_from_the_address_not_the_name():
    """Страну считает таблица по адресу; имя сервера в этом не участвует."""
    from app import geoip

    assert geoip.country_of("193.166.3.2") == "FI"
    assert geoip.country_of("2.134.0.1") == "KZ"
    # Внутренний адрес страны не имеет: у сервера за NAT вышел бы случайный флаг.
    assert geoip.country_of("192.168.0.9") == ""
    assert geoip.country_of("") == ""
    assert geoip.country_of("не адрес") == ""


async def _logged(client, owner_headers, action: str) -> list[dict]:
    res = await client.get(
        "/api/audit", headers=owner_headers, params={"action": action, "limit": 500}
    )
    assert res.status_code == 200, res.text
    return res.json()["entries"]


async def _set_value(client, owner_headers, env_id: int, value: str) -> None:
    res = await client.put(
        f"/api/environments/{env_id}/secrets",
        headers=owner_headers,
        json={"name": "DB_PASSWORD", "value": value},
    )
    assert res.status_code in (200, 201), res.text


async def test_repeated_reads_do_not_flood_the_log(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Агент спрашивает панель каждую минуту, и раньше каждый круг давал строки
    в журнале: с одного сервера тысячи в сутки. Теперь строка появляется на
    новый набор значений и на новый адрес, а повторы только считаются."""
    await _set_value(client, owner_headers, env_id, "один")
    machine = await _machine(client, owner_headers)
    await _grant(client, owner_headers, machine["id"], env_id)

    async def read(ip: str = "198.51.100.7", route: str = "secrets") -> None:
        headers = {
            "Authorization": "Bearer " + await _token(client, machine),
            "X-Forwarded-For": ip,
        }
        res = await client.get(
            f"/api/v1/machine/{route}",
            headers=headers,
            params={"project": "billing", "env": "prod"},
        )
        assert res.status_code == 200, res.text

    for _ in range(5):
        await read()
    assert len(await _logged(client, owner_headers, "machine_read")) == 1
    # выдача токена значений не открывает и в журнал не идет вовсе
    assert await _logged(client, owner_headers, "machine_token_issued") == []

    await _set_value(client, owner_headers, env_id, "два")
    await read()
    reads = await _logged(client, owner_headers, "machine_read")
    assert len(reads) == 2
    assert reads[0]["detail"] == "ключей: 1, повторных чтений с прошлой записи: 4"

    # тот же набор с другого адреса - это уже другое событие
    await read("203.0.113.9")
    assert len(await _logged(client, owner_headers, "machine_read")) == 3
    # а чередование известных адресов строк не плодит: так выходят наружу поды
    # одного ServiceAccount с разных нод
    for ip in ("198.51.100.7", "203.0.113.9", "198.51.100.7"):
        await read(ip)
    await read(route="env")
    assert len(await _logged(client, owner_headers, "machine_read")) == 3


async def test_quiet_read_is_logged_again_a_day_later(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Раз в сутки строка все равно появляется: по журналу должно быть видно
    каждый день, в который машина читала окружение."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from app.config import get_settings
    from app.db import create_engine_and_factory
    from app.models import MachineRead

    await _set_value(client, owner_headers, env_id, "один")
    machine = await _machine(client, owner_headers)
    await _grant(client, owner_headers, machine["id"], env_id)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}
    params = {"project": "billing", "env": "prod"}
    for _ in range(3):
        res = await client.get("/api/v1/machine/secrets", headers=headers, params=params)
        assert res.status_code == 200
    assert len(await _logged(client, owner_headers, "machine_read")) == 1

    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        await session.execute(
            update(MachineRead).values(
                recorded_at=datetime.now(timezone.utc) - timedelta(days=1, minutes=1)
            )
        )
        await session.commit()
    await engine.dispose()

    await client.get("/api/v1/machine/secrets", headers=headers, params=params)
    reads = await _logged(client, owner_headers, "machine_read")
    assert len(reads) == 2
    assert reads[0]["detail"].endswith("повторных чтений с прошлой записи: 2")


async def test_reports_are_logged_only_when_something_changes(
    client: httpx.AsyncClient, owner_headers, env_id
):
    machine = await _machine(client, owner_headers)
    await _grant(client, owner_headers, machine["id"], env_id)
    headers = {"Authorization": "Bearer " + await _token(client, machine)}

    async def report(version: str, applied: str, local_ip: str = "10.0.0.5") -> None:
        res = await client.post(
            "/api/v1/machine/report",
            headers=headers,
            json={
                "agent_version": version,
                "applied": applied,
                "project": "billing",
                "env": "prod",
                "path": "/run/sekvyr/billing.env",
                "local_ip": local_ip,
            },
        )
        assert res.status_code == 200, res.text

    for _ in range(3):
        await report("0.28.0", "ключей 7")
    # внутренний адрес у подов одной личности разный, это не событие
    await report("0.28.0", "ключей 7", local_ip="10.0.0.6")
    assert len(await _logged(client, owner_headers, "machine_reported")) == 1

    await report("0.28.0", "ключей 8")
    await report("0.29.0", "ключей 8")
    await report("0.29.0", "ключей 8")
    details = [e["detail"] for e in await _logged(client, owner_headers, "machine_reported")]
    assert details == ["0.29.0 ключей 8", "0.28.0 ключей 8", "0.28.0 ключей 7"]


async def test_install_command_speaks_the_language_of_the_interface(
    client: httpx.AsyncClient, owner_headers, env_id
):
    """Команда из русской панели ставит агента, который говорит по-русски, в
    том числе в журнале службы: язык уходит установщику флагом."""
    for lang, env in (("ru", env_id), ("en", None)):
        res = await client.post(
            "/api/machines/enroll-token",
            headers=owner_headers,
            json={"environment_id": env, "lang": lang},
        )
        assert res.status_code == 200, res.text
        assert res.json()["command"].endswith(f" --lang {lang}")
    plain = await client.post(
        "/api/machines/enroll-token", headers=owner_headers, json={"environment_id": env_id}
    )
    assert "--lang" not in plain.json()["command"]
    bad = await client.post(
        "/api/machines/enroll-token",
        headers=owner_headers,
        json={"environment_id": env_id, "lang": "ru; rm -rf /"},
    )
    assert bad.status_code == 422


# --- ответственный распоряжается машинами, но не обходит политики ----------

MAINT_PASS = "maint-pass-2026"


async def _maintainer(client, owner_headers, env_id: int | None = None) -> dict[str, str]:
    """Ответственный; с правом читать env_id, если оно задано."""
    res = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "maint", "password": MAINT_PASS, "role": "maintainer"},
    )
    assert res.status_code == 201, res.text
    if env_id is not None:
        granted = await client.post(
            "/api/policies",
            headers=owner_headers,
            json={
                "subject_type": "user",
                "subject_id": res.json()["id"],
                "environment_id": env_id,
                "path_prefix": "/",
                "actions": ["list", "read"],
                "effect": "allow",
            },
        )
        assert granted.status_code == 201, granted.text
    return await login(client, "maint", MAINT_PASS)


async def test_maintainer_cannot_hand_a_machine_what_they_cannot_read(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Подключить свою машину к окружению, выписать на него токен подключения,
    перевыпустить секрет машины, которая его читает: все это равно чтению
    значений машинным контуром. Без права читать самому - отказ."""
    maint = await _maintainer(client, owner_headers)
    mine = await _machine(client, maint, name="maint-box")
    res = await client.post(
        f"/api/machines/{mine['id']}/attach", headers=maint, json={"environment_id": env_id}
    )
    assert res.status_code == 403
    res = await client.post(
        "/api/machines/enroll-token",
        headers=maint,
        json={"environment_id": env_id, "allow_ips": "", "minutes": 15},
    )
    assert res.status_code == 403

    prod = await _machine(client, owner_headers, name="prod-box")
    await _grant(client, owner_headers, prod["id"], env_id)
    res = await client.post(f"/api/machines/{prod['id']}/secret", headers=maint)
    assert res.status_code == 403
    # Отказ ничего не поменял: прежний секрет машины работает.
    assert await _token(client, prod)
    # И своей машине ответственный окружение так и не выдал.
    token = await _token(client, mine)
    read = await client.get(
        "/api/v1/machine/secrets",
        headers={"Authorization": f"Bearer {token}"},
        params={"project": "billing", "env": "prod"},
    )
    assert read.status_code == 403


async def test_maintainer_hands_out_what_they_read(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    maint = await _maintainer(client, owner_headers, env_id=env_id)
    mine = await _machine(client, maint, name="maint-box")
    res = await client.post(
        f"/api/machines/{mine['id']}/attach", headers=maint, json={"environment_id": env_id}
    )
    assert res.status_code == 200, res.text
    res = await client.post(
        "/api/machines/enroll-token",
        headers=maint,
        json={"environment_id": env_id, "allow_ips": "", "minutes": 15},
    )
    assert res.status_code == 200, res.text
    res = await client.post(f"/api/machines/{mine['id']}/secret", headers=maint)
    assert res.status_code == 200, res.text


async def test_maintainer_cannot_loosen_a_machine_they_cannot_read(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Включить машину, сменить ей адреса или срок - это решать, откуда и до
    какого числа ее секрет открывает окружение. Без права читать его - отказ.
    Название менять можно, и каждая правка попадает в журнал."""
    box = await client.post("/api/machines", headers=owner_headers, json={"name": "prod-box"})
    machine_id = box.json()["id"]
    await client.post(
        f"/api/machines/{machine_id}/attach",
        headers=owner_headers,
        json={"environment_id": env_id},
    )
    await client.patch(
        f"/api/machines/{machine_id}",
        headers=owner_headers,
        json={"disabled": True, "allow_ips": "10.0.0.0/8"},
    )
    headers = await _maintainer(client, owner_headers)
    for body in ({"disabled": False}, {"allow_ips": ""}, {"expires_at": "2099-01-01"}):
        res = await client.patch(f"/api/machines/{machine_id}", headers=headers, json=body)
        assert res.status_code == 403, f"{body}: {res.text}"
    renamed = await client.patch(
        f"/api/machines/{machine_id}", headers=headers, json={"name": "prod-box-2"}
    )
    assert renamed.status_code == 200, renamed.text
    log = await client.get("/api/audit", headers=owner_headers, params={"limit": 20})
    assert any(e["action"] == "machine_updated" for e in log.json()["entries"])

    bad = await client.patch(
        f"/api/machines/{machine_id}", headers=owner_headers, json={"allow_ips": "10.0.0.0/33"}
    )
    assert bad.status_code == 400


async def test_one_broken_machine_does_not_lock_its_neighbours(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Удаленная или перевыпущенная машина с живым агентом за общим адресом
    (поды за SNAT, офис) не запирает выдачу токенов соседям."""
    good = await client.post("/api/machines", headers=owner_headers, json={"name": "good"})
    broken = await client.post("/api/machines", headers=owner_headers, json={"name": "broken"})
    for _ in range(ratelimit.MAX_FAILURES + 2):
        await client.post(
            "/api/v1/machine/token",
            json={"client_id": broken.json()["client_id"], "client_secret": "старый секрет"},
        )
    for _ in range(ratelimit.MAX_FAILURES + 2):
        await client.post(
            "/api/v1/machine/token",
            json={"client_id": "skv-deleted-long-ago", "client_secret": "x"},
        )
    res = await client.post(
        "/api/v1/machine/token",
        json={"client_id": good.json()["client_id"], "client_secret": good.json()["client_secret"]},
    )
    assert res.status_code == 200, res.text
    # Известной машине - 401 с настоящей причиной, а не 429: секрет не
    # подобрать, а журнал от ее отказов бережет запись раз в час (см. _deny).
    # Неизвестной - лимитер по адресу.
    again = await client.post(
        "/api/v1/machine/token",
        json={"client_id": broken.json()["client_id"], "client_secret": "старый секрет"},
    )
    assert again.status_code == 401
    locked = await client.post(
        "/api/v1/machine/token",
        json={"client_id": "skv-deleted-long-ago", "client_secret": "x"},
    )
    assert locked.status_code == 429


async def test_enroll_token_works_only_from_its_addresses(
    client: httpx.AsyncClient, owner_headers, env_id, unsealed
):
    """Адреса токена - адреса будущей машины: подсмотренный токен с другого
    адреса не гасится и личность не заводит."""
    made = await client.post(
        "/api/machines/enroll-token",
        headers=owner_headers,
        json={"environment_id": env_id, "allow_ips": "10.0.0.0/8"},
    )
    assert made.status_code == 200, made.text
    res = await client.post(
        "/api/v1/machine/enroll",
        json={"token": made.json()["token"], "hostname": "elsewhere", "agent_version": "1.0.0"},
    )
    assert res.status_code == 401
    machines = await client.get("/api/machines", headers=owner_headers)
    assert all(m["name"] != "elsewhere" for m in machines.json())
