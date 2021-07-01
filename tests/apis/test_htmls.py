import asyncio

import pytest
from fastapi.testclient import TestClient

from tests.helper import first_snapshot_id_sync


@pytest.mark.usefixtures("snapshots_setup")
def test_html(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    id_ = first_snapshot_id_sync(event_loop)

    response = client.get(f"/api/snapshots/{id_}")
    snapshot = response.json()

    sha256 = snapshot.get("html", {}).get("sha256", "")
    response = client.get(f"/api/htmls/{sha256}")
    assert response.status_code == 200

    sha256 = snapshot.get("html", {}).get("sha256", "")
    response = client.get(f"/api/htmls/{sha256}/text")
    assert response.status_code == 200
