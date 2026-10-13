"""Обход всех маршрутов с окружением или проектом в пути.

Самопроверка гарантирует, что у каждого маршрута есть охрана. Этот тест
проверяет, что охрана смотрит туда, куда надо: человек без прав на окружение
или проект не получает от маршрута ни успеха, ни падения, какие бы правдоподобные
параметры он ни подставил. Маршрут, который проверяет права на одно место, а
действует в другом, здесь ответил бы успехом.

Список маршрутов берется из схемы приложения, а не из этого файла: новый
маршрут попадает в обход сам.
"""

import httpx

from tests.conftest import login

PASS = "sweep-pass-2026"
SEALED = "e2e1:" + "A" * 40


async def _setup(client, owner_headers) -> dict:
    """Проект alpha (own - с правами у разработчика, foreign - без) и beta."""
    ids: dict = {}
    for slug, envs in (("alpha", ["own", "foreign"]), ("beta", ["prod"])):
        res = await client.post(
            "/api/projects", headers=owner_headers, json={"slug": slug, "environments": envs}
        )
        assert res.status_code == 201, res.text
        project = res.json()
        ids[slug] = project["id"]
        rows = (
            await client.get(f"/api/projects/{project['id']}/environments", headers=owner_headers)
        ).json()
        for row in rows:
            ids[f"{slug}/{row['name']}"] = row["id"]
            res = await client.put(
                f"/api/environments/{row['id']}/secrets",
                headers=owner_headers,
                json={"name": "PROBE", "value": "probe-value", "path": "/"},
            )
            assert res.status_code == 200, res.text
    for env in ("alpha/foreign", "beta/prod"):
        res = await client.post(
            f"/api/environments/{ids[env]}/snapshots", headers=owner_headers, json={"name": "s1"}
        )
        assert res.status_code in (200, 201), res.text
        ids[f"{env}:snapshot"] = res.json()["id"]

    res = await client.post(
        "/api/users",
        headers=owner_headers,
        json={"username": "dev", "password": PASS, "role": "developer"},
    )
    assert res.status_code == 201, res.text
    res = await client.post(
        "/api/policies",
        headers=owner_headers,
        json={
            "subject_type": "user",
            "subject_id": res.json()["id"],
            "environment_id": ids["alpha/own"],
            "path_prefix": "/",
            "actions": ["list", "read", "write", "delete"],
            "effect": "allow",
        },
    )
    assert res.status_code == 201, res.text
    return ids


def _resolve(schema: dict, node: dict) -> dict:
    while "$ref" in node:
        node = schema["components"]["schemas"][node["$ref"].split("/")[-1]]
    return node


# Значения по имени поля: правдоподобные, чтобы до проверки прав дошло дело,
# а не до отказа разбора (422 здесь означает, что обход подставил чепуху).
BY_NAME = {
    "name": "PROBE",
    "new_name": "PROBE2",
    "path": "/",
    "new_path": "/",
    "value": "x",
    "comment": "",
    "note": "",
    "code": "placeholder",
    "text": "A=1\n",
    "title": "t",
    "group_name": "",
    "required_keys": "",
    "slug": "probe",
    "confirm": "probe",
    "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
    "nonce": "AAAAAAAAAAAAAAAA",
    "verifier_nonce": "AAAAAAAAAAAAAAAA",
    "wrapped_key": "A" * 64,
    "verifier": "A" * 64,
    "ephemeral_public": "A" * 88,
}


def _value(schema: dict, name: str, prop: dict, ctx: dict):
    prop = _resolve(schema, prop)
    if name in ctx:
        return ctx[name]
    if name in BY_NAME:
        return BY_NAME[name]
    if "anyOf" in prop:
        options = [o for o in prop["anyOf"] if o.get("type") != "null"]
        return _value(schema, name, options[0], ctx) if options else None
    kind = prop.get("type")
    if kind == "integer":
        return max(1, prop.get("minimum", 1))
    if kind == "boolean":
        return False
    if kind == "array":
        return []
    if kind == "object":
        return {}
    return "x"


def _body(schema: dict, op: dict, ctx: dict):
    content = op.get("requestBody", {}).get("content", {})
    if "application/json" not in content:
        return None
    model = _resolve(schema, content["application/json"]["schema"])
    required = set(model.get("required", []))
    return {
        name: _value(schema, name, prop, ctx)
        for name, prop in model.get("properties", {}).items()
        if name in required or name in ctx or name in ("path", "version")
    }


async def _sweep(client, headers, schema: dict, ctx: dict, only: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for path, ops in schema["paths"].items():
        if only not in path:
            continue
        for method, op in ops.items():
            url = path
            for key in ("env_id", "project_id", "snapshot_id"):
                url = url.replace("{" + key + "}", str(ctx[key]))
            params = {
                p["name"]: _value(schema, p["name"], p.get("schema", {}), ctx)
                for p in op.get("parameters", [])
                if p["in"] == "query"
            }
            res = await client.request(
                method.upper(), url, headers=headers, params=params, json=_body(schema, op, ctx)
            )
            out[f"{method.upper()} {path}"] = res.status_code
    return out


async def test_foreign_environment_and_project_are_closed(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    ids = await _setup(client, owner_headers)
    dev = await login(client, "dev", PASS)
    schema = client._transport.app.openapi()  # noqa: SLF001

    problems = []
    for target, project in (("alpha/foreign", "alpha"), ("beta/prod", "beta")):
        ctx = {
            "env_id": ids[target],
            "project_id": ids["beta"],
            "snapshot_id": ids[f"{target}:snapshot"],
            "environment_id": ids[target],
            "other": ids["alpha/own"],
            "source": "own",
            "targets": [ids[target]],
            "version": 1,
            "machine_id": 1,
        }
        for only in ("{env_id}", "{project_id}"):
            for route, code in (await _sweep(client, dev, schema, ctx, only)).items():
                if code not in (403, 404):
                    problems.append(f"{target}: {route} -> {code}")
    assert not problems, "\n".join(problems)


async def test_sweep_reaches_routes_where_rights_exist(
    client: httpx.AsyncClient, owner_headers, unsealed
):
    """Тот же обход по своему окружению: если бы обход подставлял чепуху, он бы
    и там получал только отказы, и проверка выше ничего бы не доказывала."""
    ids = await _setup(client, owner_headers)
    dev = await login(client, "dev", PASS)
    schema = client._transport.app.openapi()  # noqa: SLF001
    ctx = {
        "env_id": ids["alpha/own"],
        "project_id": ids["alpha"],
        "snapshot_id": 0,
        "environment_id": ids["alpha/own"],
        "other": ids["alpha/foreign"],
        "source": "foreign",
        "targets": [],
        "version": 1,
        "machine_id": 1,
    }
    codes = await _sweep(client, dev, schema, ctx, "{env_id}")
    ok = sorted(route for route, code in codes.items() if 200 <= code < 300)
    assert "GET /api/environments/{env_id}/secrets" in ok
    assert "GET /api/environments/{env_id}/secret" in ok
    assert "PUT /api/environments/{env_id}/secrets" in ok
    assert len(ok) >= 10, ok
    assert not [route for route, code in codes.items() if code >= 500], codes
