import httpx
import pytest

from app.models.match import Match
from tests.helper import first_rule_id, first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_matches_search(client: httpx.AsyncClient):
    count = await Match.all().count()

    response = await client.get("/api/matches/search")
    assert response.status_code == 200

    data = response.json()
    matches = data.get("results")
    assert len(matches) == count

    first = matches[0]
    assert isinstance(first.get("snapshot"), dict)
    assert isinstance(first.get("rule"), dict)

    total = data.get("total")
    assert total == count


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_matches_search_with_filters(client: httpx.AsyncClient):
    snapshot_id = await first_snapshot_id()
    response = await client.get(
        "/api/matches/search", params={"snapshot_id": snapshot_id}
    )
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 1

    rule_id = await first_rule_id()
    response = await client.get("/api/matches/search", params={"rule_id": rule_id})
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 1

    response = await client.get(
        "/api/matches/search", params={"rule_id": rule_id, "snapshot_id": snapshot_id}
    )
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_matches_search_with_daterange(client: httpx.AsyncClient):
    response = await client.get("/api/matches/search", params={"from_at": "1970-01-01"})
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == await Match.all().count()

    response = await client.get("/api/matches/search", params={"to_at": "1970-01-01"})
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 0
