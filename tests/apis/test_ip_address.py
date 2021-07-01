import asyncio

import pytest
import vcr
from fastapi.testclient import TestClient


@vcr.use_cassette(
    "tests/fixtures/vcr_cassettes/ip_address.yaml", ignore_hosts=["testserver"]
)
@pytest.mark.usefixtures("patch_whois_lookup")
def test_get(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    ip_address = "93.184.216.34"
    response = client.get(f"/api/ip_address/{ip_address}")
    assert response.status_code == 200

    data = response.json()
    ip_address_ = data.get("ipAddress", "")
    assert ip_address_ == ip_address

    snapshots = data.get("snapshots", [])
    assert len(snapshots) == 0

    whois = data.get("whois", "")
    assert whois


def test_get_with_invalid_input(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    response = client.get("/api/ip_address/example.com")
    assert response.status_code == 404
