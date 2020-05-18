import pytest

from uzen.models.screenshots import Screenshot
from uzen.models.snapshots import Snapshot
from uzen.services.browser import Browser


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_screenshots(client):
    first = await Snapshot.all().first()
    snapshot_id = first.id

    response = await client.get(f"/api/screenshots/{snapshot_id}")
    assert response.status_code == 200

    json = response.json()
    assert json.get("data") == ""


async def mock_preview(hostname: str):
    s = Screenshot()
    s.data = "foo"
    return s


@pytest.mark.asyncio
async def test_preview(client, monkeypatch):
    monkeypatch.setattr(Browser, "preview", mock_preview)

    response = await client.get("/api/screenshots/preview/example.com")
    assert response.status_code == 200

    json = response.json()
    assert json.get("data") == "foo"
