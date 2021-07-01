import asyncio

import pytest
from fastapi.testclient import TestClient

from tests.helper import first_snapshot_id_sync


@pytest.mark.usefixtures("snapshots_setup")
def test_screenshots(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    snapshot_id = first_snapshot_id_sync(event_loop)

    response = client.get(f"/api/screenshots/{snapshot_id}")
    assert response.status_code == 200
    assert response.headers.get("content-type") == "image/png"


# Disable this test because it's difficult to work the test along with arq
# async def mock_preview(hostname: str):
#     return b""
#
#
# @pytest.mark.asyncio
# async def test_preview(
#     client: TestClient, monkeypatch: MonkeyPatch, arq_worker: Worker
# ):
#     monkeypatch.setattr(Browser, "preview", mock_preview)
#
#     response = await client.get("/api/screenshots/preview/example.com")
#     assert response.status_code in [200, 500]
#     assert response.headers.get("content-type") == "image/png"
#
