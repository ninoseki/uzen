import pytest

from uzen.models.snapshots import Snapshot


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_screenshots(client):
    first = await Snapshot.all().first()
    snapshot_id = first.id

    response = await client.get(f"/api/screenshots/{snapshot_id}")
    assert response.status_code == 200

    json = response.json()
    assert json.get("data") == ""
