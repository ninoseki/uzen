import asyncio

import pytest
from fastapi.testclient import TestClient

from tests.helper import first_snapshot_id_sync


@pytest.mark.usefixtures("snapshots_setup")
def test_har(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    snapshot_id = first_snapshot_id_sync(event_loop)

    response = client.get(f"/api/hars/{snapshot_id}")
    assert response.status_code == 200
