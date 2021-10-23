from typing import List

from fastapi.testclient import TestClient

from app import models


def test_screenshots(client: TestClient, snapshots: List[models.Snapshot]):
    snapshot_id = snapshots[0].id

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
