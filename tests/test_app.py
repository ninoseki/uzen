import httpx
import pytest


@pytest.mark.asyncio
async def test_app(client: httpx.AsyncClient):
    response = await client.get("/")
    assert response.status_code == 200

    response = await client.get("/foo")
    assert response.status_code == 404
