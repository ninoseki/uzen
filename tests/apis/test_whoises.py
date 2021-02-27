import pytest
from httpx import AsyncClient

from tests.helper import first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_whois(client: AsyncClient):
    id_ = await first_snapshot_id()
    response = await client.get(f"/api/snapshots/{id_}")

    snapshot = response.json()

    whois_id = snapshot.get("whois", {}).get("id", "")
    response = await client.get(f"/api/whoises/{whois_id}")
    assert response.status_code == 200
