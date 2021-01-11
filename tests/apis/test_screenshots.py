import pytest

from app.models.snapshots import Snapshot
from app.services.browser import Browser


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_screenshots(client):
    first = await Snapshot.all().first()
    snapshot_id = first.id

    response = await client.get(f"/api/screenshots/{snapshot_id}")
    assert response.status_code == 200
    assert response.headers.get("content-type") == "image/png"


async def mock_preview(hostname: str):
    return b""


@pytest.mark.asyncio
async def test_preview(client, monkeypatch):
    monkeypatch.setattr(Browser, "preview", mock_preview)

    response = await client.get("/api/screenshots/preview/example.com")
    assert response.status_code == 200
    assert response.headers.get("content-type") == "image/png"
