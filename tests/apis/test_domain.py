import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.mark.usefixtures("patch_whois_lookup")
def test_get(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    hostname = "example.com"
    response = client.get(f"/api/domain/{hostname}")
    assert response.status_code == 200

    data = response.json()
    assert data.get("hostname") == hostname

    snapshots = data.get("snapshots", [])
    assert len(snapshots) == 0

    whois = data.get("whois", "")
    assert whois


def test_get_with_invalid_input(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    response = client.get("/api/domain/1.1.1.1")
    assert response.status_code == 404
