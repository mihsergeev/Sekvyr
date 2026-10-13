"""Номера вне диапазона столбца: 404, а не 500.

Нашел фаззинг схемы (schemathesis): у Postgres любой номер больше
2 147 483 647 в пути или в теле запроса ронял ручку с 500, у SQLite - больше
2^63.
"""

import httpx
import pytest
from sqlalchemy.exc import DBAPIError

HUGE = 10**25


async def test_huge_numbers_in_paths_and_bodies(client: httpx.AsyncClient, owner_headers, env_id):
    for method, path, body in (
        ("GET", f"/api/environments/{HUGE}/snapshots", None),
        ("GET", f"/api/environments/{env_id}/diff?other={HUGE}", None),
        ("POST", f"/api/projects/{HUGE}/environments", {"name": "x"}),
        ("DELETE", f"/api/machines/clusters/{HUGE}", None),
        ("GET", f"/api/policies?subject_type=machine&subject_id=-{HUGE}", None),
    ):
        res = await client.request(method, path, headers=owner_headers, json=body)
        assert res.status_code in (400, 403, 404, 422), (method, path, res.status_code, res.text)


@pytest.mark.parametrize(
    "message,code",
    [
        ("invalid input for query argument $1: 3000000000 (value out of int32 range)", 404),
        ('value too long for type character varying(200)', 400),
        ('invalid byte sequence for encoding "UTF8": 0x00', 400),
    ],
)
async def test_postgres_range_errors_are_not_500(client: httpx.AsyncClient, message, code):
    """Тот же случай у Postgres приходит как DBAPIError с текстом asyncpg."""
    app = client._transport.app  # noqa: SLF001

    async def boom():
        raise DBAPIError("SELECT 1", {}, Exception(message))

    app.add_api_route("/api/test-db-error", boom, methods=["GET"])
    res = await client.get("/api/test-db-error")
    assert res.status_code == code, res.text


async def test_deleted_snapshot_takes_its_rows_along(client: httpx.AsyncClient, owner_headers, env_id):
    """SQLite отдает номер удаленного снимка следующему. Без внешних ключей
    строки прежнего снимка оставались, и новый падал с 500 (нашел фаззинг)."""
    await client.put(
        f"/api/environments/{env_id}/secrets", headers=owner_headers, json={"name": "A", "value": "1"}
    )
    first = await client.post(
        f"/api/environments/{env_id}/snapshots", headers=owner_headers, json={"name": "one"}
    )
    assert first.status_code == 201, first.text
    gone = await client.delete(
        f"/api/environments/{env_id}/snapshots/{first.json()['id']}", headers=owner_headers
    )
    assert gone.status_code == 204, gone.text
    second = await client.post(
        f"/api/environments/{env_id}/snapshots", headers=owner_headers, json={"name": "two"}
    )
    assert second.status_code == 201, second.text
