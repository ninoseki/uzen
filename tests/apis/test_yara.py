import json

import httpx
import pytest


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan(client: httpx.AsyncClient):
    # it matches with all snapshots
    payload = {"source": 'rule foo: bar {strings: $a = "foo" condition: $a}'}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshot = response.json()
    assert snapshot.get("id")
    assert snapshot.get("type") == "yara"


@pytest.mark.asyncio
async def test_yara_scan_with_invalid_input(client: httpx.AsyncClient):
    payload = {"source": "boo"}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 422
