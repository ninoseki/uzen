import httpx
import pytest

from app.models.snapshot import Snapshot


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_screenshots(client: httpx.AsyncClient):
    first = await Snapshot.all().first()
    snapshot_id = first.id

    response = await client.get(f"/api/hars/{snapshot_id}")
    assert response.status_code == 200
