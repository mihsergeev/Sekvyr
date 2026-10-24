"""Смена родителя окружения ниже порога подтверждения (1.0.1).

Падает на 1.0.0: новый родитель менял все унаследованные значения прода сразу,
хотя прямая правка того же человека ждала подтверждения.
"""

from tests.conftest import login
from tests.pass11_helpers import (
    PASS,
    _policy,
    _project_id,
    _put,
    _threshold,
    _user,
    _values,
)


# --- 1. смена родителя и порог ---------------------------------------------


async def test_reparent_below_threshold_is_refused(client, owner_headers, env_id):
    oh = owner_headers
    pid = await _project_id(client, oh)
    staging = await client.post(
        f"/api/projects/{pid}/environments", headers=oh, json={"name": "staging"}
    )
    assert staging.status_code == 201, staging.text
    staging_id = staging.json()["id"]
    assert (await _put(client, oh, staging_id, "FROM_STAGING", "staging-value")).status_code == 200

    await _threshold(client, oh, 40)
    mid = await _user(client, oh, "lead", "maintainer")
    await _policy(
        client, oh, subject_type="user", subject_id=mid, project_id=pid,
        actions=["list", "read", "write"],
    )
    lead = await login(client, "lead", PASS)
    res = await client.patch(
        f"/api/environments/{env_id}", headers=lead, json={"parent_id": staging_id}
    )
    assert res.status_code == 403, res.text
    assert ("/", "FROM_STAGING") not in await _values(client, oh, env_id)

    # Владелец порог не обходит, а задает: ему можно.
    res = await client.patch(f"/api/environments/{env_id}", headers=oh, json={"parent_id": staging_id})
    assert res.status_code == 200, res.text
    assert (await _values(client, oh, env_id))[("/", "FROM_STAGING")] == "staging-value"
