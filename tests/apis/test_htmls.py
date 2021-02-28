import pytest
from httpx import AsyncClient

from tests.helper import first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_whois(client: AsyncClient):
    id_ = await first_snapshot_id()
    response = await client.get(f"/api/snapshots/{id_}")

    snapshot = response.json()

    sha256 = snapshot.get("html", {}).get("sha256", "")
    response = await client.get(f"/api/htmls/{sha256}")
    assert response.status_code == 200
