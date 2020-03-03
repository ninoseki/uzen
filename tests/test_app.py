from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import pytest
import json


@pytest.mark.asyncio
async def test_app(client):
    response = await client.get("/")
    assert response.status_code == 200

    response = await client.get("/foo")
    assert response.status_code == 404
