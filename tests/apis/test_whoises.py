import asyncio

import pytest
from fastapi.testclient import TestClient

from tests.helper import first_snapshot_id_sync


@pytest.mark.usefixtures("snapshots_setup")
def test_whois(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    id_ = first_snapshot_id_sync(event_loop)
    response = client.get(f"/api/snapshots/{id_}")

    snapshot = response.json()

    whois_id = snapshot.get("whois", {}).get("id", "")
    response = client.get(f"/api/whoises/{whois_id}")
    assert response.status_code == 200
