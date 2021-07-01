import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.mark.usefixtures("snapshots_setup")
def test_yara_scan(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    # it matches with all snapshots
    payload = {"source": 'rule foo: bar {strings: $a = "foo" condition: $a}'}
    response = client.post("/api/yara/scan", json=payload)
    assert response.status_code == 200

    snapshot = response.json()
    assert snapshot.get("id")
    assert snapshot.get("type") == "yara"


def test_yara_scan_with_invalid_input(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    payload = {"source": "boo"}
    response = client.post("/api/yara/scan", json=payload)
    assert response.status_code == 422
