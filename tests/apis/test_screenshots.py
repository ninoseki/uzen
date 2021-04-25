import httpx
import pytest

from app.models.snapshot import Snapshot


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_screenshots(client: httpx.AsyncClient):
    first = await Snapshot.all().first()
    snapshot_id = first.id

    response = await client.get(f"/api/screenshots/{snapshot_id}")
    assert response.status_code == 200
    assert response.headers.get("content-type") == "image/png"


# Disable this test because it's difficult to work the test along with arq
# async def mock_preview(hostname: str):
#     return b""
#
#
# @pytest.mark.asyncio
# async def test_preview(
#     client: httpx.AsyncClient, monkeypatch: MonkeyPatch, arq_worker: Worker
# ):
#     monkeypatch.setattr(Browser, "preview", mock_preview)
#
#     response = await client.get("/api/screenshots/preview/example.com")
#     assert response.status_code in [200, 500]
#     assert response.headers.get("content-type") == "image/png"
#
