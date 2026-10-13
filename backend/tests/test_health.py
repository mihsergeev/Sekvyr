import httpx


async def test_health_reports_db(client: httpx.AsyncClient):
    res = await client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["db"] == "ok"
    assert body["version"]
    # сейф еще не заведен, поэтому панель честно говорит, что значений не отдает
    assert body["sealed"] is True
    assert body["status"] == "sealed"


async def test_health_is_ok_when_unsealed(client: httpx.AsyncClient, unsealed):
    body = (await client.get("/api/health")).json()
    assert body["status"] == "ok"
    assert body["sealed"] is False


async def test_docs_are_hidden(client: httpx.AsyncClient):
    """Схему API наружу не публикуем: рядом будет открытый машинный контур."""
    assert (await client.get("/api/openapi.json")).status_code == 404
