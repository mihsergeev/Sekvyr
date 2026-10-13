"""Находки седьмого прохода проверки, кроме прав по папкам (test_folder_rights.py).

Каждый тест воспроизводит сценарий из разбора и падает на коде до исправления.
"""

import json

import httpx
from sqlalchemy import func, select

from app import backups, heartbeat
from app.api import migrate as migrate_api
from app.api.ops import _mask_url
from app.importers import Fetched, Item
from tests.conftest import login
from tests.test_approval import PASS, _grant, _set_threshold, _user


async def _project(client, owner, slug="shop", envs=("dev", "prod")):
    res = await client.post("/api/projects", headers=owner, json={"slug": slug, "environments": list(envs)})
    assert res.status_code == 201, res.text
    pid = res.json()["id"]
    got = (await client.get(f"/api/projects/{pid}/environments", headers=owner)).json()
    return pid, {e["name"]: e["id"] for e in got}


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


async def _child(client, owner, pid, parent_id, name="stage"):
    res = await client.post(
        f"/api/projects/{pid}/environments", headers=owner, json={"name": name, "parent_id": parent_id}
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


async def test_snapshot_restore_returns_a_child_to_inheritance(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Снимок дочернего окружения, где ключ брался у родителя. Восстановление
    ставило "удалить", и приложение лишалось переменной вовсе."""
    pid, envs = await _project(client, owner_headers)
    await _put(client, owner_headers, envs["prod"], "SMTP", "from-parent")
    child = await _child(client, owner_headers, pid, envs["prod"])
    made = await client.post(f"/api/environments/{child}/snapshots", headers=owner_headers, json={"name": "s"})
    assert made.status_code == 201, made.text
    await _put(client, owner_headers, child, "SMTP", "override")
    restored = await client.post(
        f"/api/environments/{child}/snapshots/{made.json()['id']}/restore", headers=owner_headers
    )
    assert restored.status_code == 200, restored.text
    assert await _value(client, owner_headers, child, "SMTP") == "from-parent"


async def test_rollback_below_threshold_is_recorded_as_a_proposal(
    client: httpx.AsyncClient, owner_headers, env_id
):
    await _put(client, owner_headers, env_id, "TOKEN", "one")
    await _put(client, owner_headers, env_id, "TOKEN", "two")
    await _set_threshold(client, owner_headers, 30)
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await _grant(client, owner_headers, dev_id, ["list", "read", "write"])
    dev = await login(client, "dev", PASS)

    res = await client.post(
        f"/api/environments/{env_id}/secret/rollback", headers=dev, json={"name": "TOKEN", "version": 1}
    )
    assert res.status_code == 200, res.text
    assert res.json()["pending"] is True
    assert await _value(client, owner_headers, env_id, "TOKEN") == "two"
    log = (await client.get("/api/audit", headers=owner_headers, params={"q": "TOKEN"})).json()["entries"]
    actions = [e["action"] for e in log if e["actor"] == "dev"]
    assert "secret_pending" in actions and "secret_rolled_back" not in actions


async def test_migrate_without_overwrite_keeps_inherited_values(
    client: httpx.AsyncClient, owner_headers, unsealed, monkeypatch
):
    pid, envs = await _project(client, owner_headers)
    await _put(client, owner_headers, envs["prod"], "SMTP", "from-parent")
    child = await _child(client, owner_headers, pid, envs["prod"])

    async def fake_fetch(_body):
        return Fetched(items=[Item(path="/", name="SMTP", value="from-vault")])

    monkeypatch.setattr(migrate_api, "_fetch", fake_fetch)
    body = {"source": "vault", "url": "https://vault.example", "token": "t", "environment_id": child}
    preview = await client.post("/api/migrate/preview", headers=owner_headers, json=body)
    assert preview.status_code == 200, preview.text
    assert preview.json()["rows"][0]["action"] == "обновить"
    applied = await client.post("/api/migrate/apply", headers=owner_headers, json=body)
    assert applied.status_code == 200, applied.text
    assert await _value(client, owner_headers, child, "SMTP") == "from-parent"


async def test_spread_into_an_inheriting_environment_is_same(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    pid, envs = await _project(client, owner_headers)
    await _put(client, owner_headers, envs["prod"], "SMTP", "same-value")
    child = await _child(client, owner_headers, pid, envs["prod"])
    await _put(client, owner_headers, envs["dev"], "SMTP", "same-value")
    res = await client.post(
        f"/api/environments/{envs['dev']}/spread",
        headers=owner_headers,
        json={"name": "SMTP", "targets": [child]},
    )
    assert res.status_code == 200, res.text
    assert res.json()["rows"] == [{"environment": "stage", "state": "same"}]
    listed = (await client.get(f"/api/environments/{child}/secrets", headers=owner_headers)).json()
    assert listed[0]["inherited_from"] == "prod"


async def test_environment_creation_needs_the_whole_project(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    pid, envs = await _project(client, owner_headers)
    keeper_id = await _user(client, owner_headers, "keeper", "maintainer")
    res = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={"subject_type": "user", "subject_id": keeper_id, "environment_id": envs["prod"],
              "actions": ["list", "read", "write"]},
    )
    assert res.status_code == 201, res.text
    keeper = await login(client, "keeper", PASS)

    denied = await client.post(f"/api/projects/{pid}/environments", headers=keeper, json={"name": "qa"})
    assert denied.status_code == 403, denied.text
    projects = (await client.get("/api/projects", headers=keeper)).json()
    assert projects[0]["manage"] is False

    # Чужой проект: тот же ответ, что и несуществующий.
    other_pid, _ = await _project(client, owner_headers, slug="billing", envs=("prod",))
    hidden = await client.post(f"/api/projects/{other_pid}/environments", headers=keeper, json={"name": "prod"})
    assert hidden.status_code == 404, hidden.text

    # Проекты заводит владелец.
    made = await client.post("/api/projects", headers=keeper, json={"slug": "mine", "environments": ["dev"]})
    assert made.status_code == 403, made.text


async def test_import_has_a_key_limit(client: httpx.AsyncClient, owner_headers, env_id):
    text = "".join(f"K{i}=v\n" for i in range(5001))
    res = await client.post(
        f"/api/environments/{env_id}/import", headers=owner_headers, json={"text": text}
    )
    assert res.status_code == 400, res.text


async def _machine(client, owner, env_id, name="node"):
    made = (await client.post("/api/machines", headers=owner, json={"name": name})).json()
    res = await client.post(
        "/api/policies",
        headers=owner,
        json={"subject_type": "machine", "subject_id": made["id"], "environment_id": env_id,
              "actions": ["list", "read"]},
    )
    assert res.status_code == 201, res.text
    token = (
        await client.post(
            "/api/v1/machine/token",
            json={"client_id": made["client_id"], "client_secret": made["client_secret"]},
        )
    ).json()["access_token"]
    return made, {"Authorization": f"Bearer {token}"}


async def test_machine_gets_one_value_per_name(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Одноименные ключи в разных папках разрешены, но машина получает одно
    значение на имя - одно и то же и списком (агент, ESO), и файлом."""
    _pid, envs = await _project(client, owner_headers)
    prod = envs["prod"]
    assert (await _put(client, owner_headers, prod, "HOST", "root")).status_code == 200
    assert (await _put(client, owner_headers, prod, "HOST", "db", path="/db")).status_code == 200
    assert (await _put(client, owner_headers, prod, "PORT", "1")).status_code == 200
    _made, head = await _machine(client, owner_headers, prod)
    query = {"project": "shop", "env": "prod"}
    listed = await client.get("/api/v1/machine/secrets", headers=head, params=query)
    assert listed.status_code == 200, listed.text
    pairs = [(v["name"], v["value"]) for v in listed.json()["values"]]
    assert sorted(pairs) == [("HOST", "db"), ("PORT", "1")]
    text = (await client.get("/api/v1/machine/env", headers=head, params=query)).json()["text"]
    assert text.count("HOST=") == 1 and "HOST=db" in text


async def test_machine_answers_alike_for_missing_and_not_granted(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    _pid, envs = await _project(client, owner_headers)
    _other, other_envs = await _project(client, owner_headers, slug="billing", envs=("prod",))
    _made, head = await _machine(client, owner_headers, envs["prod"])
    missing = await client.get("/api/v1/machine/secrets", headers=head, params={"project": "nope", "env": "prod"})
    foreign = await client.get("/api/v1/machine/secrets", headers=head, params={"project": "billing", "env": "prod"})
    assert missing.status_code == foreign.status_code == 403
    assert missing.json() == foreign.json()


async def test_machine_follows_a_project_moved_to_another_group(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    pid, envs = await _project(client, owner_headers)
    await _put(client, owner_headers, envs["prod"], "A", "1")
    _made, head = await _machine(client, owner_headers, envs["prod"])
    moved = await client.patch(f"/api/projects/{pid}", headers=owner_headers, json={"group_name": "Acme"})
    assert moved.status_code == 200, moved.text
    res = await client.get(
        "/api/v1/machine/secrets", headers=head, params={"project": "shop", "env": "prod", "group": "old"}
    )
    assert res.status_code == 200, res.text


async def test_machine_denials_do_not_flood_the_log(client: httpx.AsyncClient, owner_headers, unsealed):
    from app.db import create_engine_and_factory
    from app.config import get_settings
    from app.models import AuditLog
    from app.api import machine as machine_api

    # Память "уже записано" общая на процесс, а номера в каждой новой базе
    # начинаются заново: отказ той же паре из другого теста глушил бы этот.
    machine_api._DENIED_LOGGED.clear()
    _pid, envs = await _project(client, owner_headers)
    made, head = await _machine(client, owner_headers, envs["prod"])
    policies = (await client.get("/api/policies", headers=owner_headers, params={"subject_type": "machine"})).json()
    for policy in policies:
        await client.delete(f"/api/policies/{policy['id']}", headers=owner_headers)
    # Окружение видно (list), а читать его нельзя (read нет): каждый запрос
    # агента - отказ.
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={"subject_type": "machine", "subject_id": made["id"], "environment_id": envs["dev"],
              "actions": ["list"]},
    )
    for _ in range(5):
        await client.get("/api/v1/machine/secrets", headers=head, params={"project": "shop", "env": "dev"})
    engine, factory = create_engine_and_factory(get_settings().db_url)
    async with factory() as session:
        denied = await session.scalar(select(func.count()).where(AuditLog.action == "machine_denied"))
    await engine.dispose()
    assert denied == 1


async def test_report_without_result_keeps_the_previous_one(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    _pid, envs = await _project(client, owner_headers)
    made, head = await _machine(client, owner_headers, envs["prod"])
    await client.post(
        "/api/v1/machine/report",
        headers=head,
        json={"agent_version": "1.0.0", "applied": "keys 3", "project": "shop", "env": "prod",
              "path": "/srv/" + "x" * 400 + "/.env"},
    )
    key_only = await client.post("/api/v1/machine/report", headers=head, json={"agent_version": "1.0.0"})
    assert key_only.status_code == 200, key_only.text
    card = next(m for m in (await client.get("/api/machines", headers=owner_headers)).json() if m["id"] == made["id"])
    assert card["applied"] == "keys 3"
    assert card["apps"], "длинный путь не уронил отчет"


async def test_search_finds_visible_keys_behind_many_foreign_ones(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    pid, envs = await _project(client, owner_headers)
    text = "".join(f"AKEY{i:04d}=v\n" for i in range(700))
    await client.post(f"/api/environments/{envs['prod']}/import", headers=owner_headers, json={"text": text})
    await _put(client, owner_headers, envs["dev"], "ZKEY", "v")
    dev_id = await _user(client, owner_headers, "dev", "developer")
    await client.post(
        "/api/policies",
        headers=owner_headers,
        json={"subject_type": "user", "subject_id": dev_id, "environment_id": envs["dev"], "actions": ["list"]},
    )
    dev = await login(client, "dev", PASS)
    hits = (await client.get("/api/search", headers=dev, params={"q": "key", "limit": 10})).json()
    assert [h["name"] for h in hits] == ["ZKEY"]


def test_backup_mark_of_a_wrong_shape(tmp_path, monkeypatch):
    from app.config import get_settings

    settings = get_settings()
    for raw in ("[]", '"x"', json.dumps({"at": "2026-10-01T00:00:00Z", "ok": True, "size": "12M"})):
        mark = tmp_path / "backup.json"
        mark.write_text(raw, encoding="utf-8")
        monkeypatch.setattr(settings, "backup_state_file", str(mark), raising=False)
        state = backups.read_state(settings)
        assert state.stale or state.ok in (True, False)


def test_webhook_credentials_are_masked():
    assert "secret" not in _mask_url("https://user:secret@hooks.example/path")
    assert _mask_url("https://user:secret@hooks.example/path").startswith("https://hooks.example/")


def test_heartbeat_keeps_one_line_per_setting(tmp_path, monkeypatch):
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(heartbeat, "path_for", lambda _s: tmp_path / "pulse")
    heartbeat.write(
        settings,
        {"telegram_token": "123:ABC\ntg_api=http://127.0.0.1:9"},
        sealed=False,
        alerts_ok=1,
    )
    lines = (tmp_path / "pulse").read_text(encoding="utf-8").splitlines()
    assert [line for line in lines if line.startswith("tg_api=")] == ["tg_api="]


def test_panel_url_without_trailing_slash(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("SEKVYR_PANEL_URL", "https://panel.example/")
    assert Settings().panel_url == "https://panel.example"


async def test_forgotten_key_file_is_not_a_configured_key(
    client: httpx.AsyncClient, owner_headers, tmp_path, monkeypatch
):
    """Путь к файлу ключа задан, а файла нет (его забыли кнопкой): для баннера
    сейфа ключа нет."""
    from app import config

    monkeypatch.setenv("SEKVYR_ROOT_KEY_FILE", (tmp_path / "gone.key").as_posix())
    config.get_settings.cache_clear()
    got = (await client.get("/api/vault/status", headers=owner_headers)).json()
    assert got["key_file_present"] is False
    assert got["root_key_configured"] is False


def test_empty_admin_user_falls_back_to_admin(monkeypatch):
    from app import config

    monkeypatch.setenv("SEKVYR_ADMIN_USER", "")
    assert config.Settings().admin_user == "admin"
