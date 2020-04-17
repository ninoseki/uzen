import pytest

from uzen.models.matches import Match


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_matches_search(client):
    match_count = await Match.all().count()

    response = await client.get("/api/matches/search")
    assert response.status_code == 200

    matches = response.json()
    assert len(matches) == match_count

    first = matches[0]
    assert isinstance(first.get("snapshot"), dict)
    assert isinstance(first.get("rule"), dict)


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_matches_search_with_filters(client):
    response = await client.get("/api/matches/search", params={"snapshot_id": 1})
    assert response.status_code == 200
    matches = response.json()
    assert len(matches) == 1

    response = await client.get("/api/matches/search", params={"rule_id": 1})
    assert response.status_code == 200
    matches = response.json()
    assert len(matches) == 1

    response = await client.get(
        "/api/matches/search", params={"rule_id": 1, "snapshot_id": 1}
    )
    assert response.status_code == 200
    matches = response.json()
    assert len(matches) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_matches_search_with_daterange(client):
    response = await client.get("/api/matches/search", params={"from_at": "1970-01-01"})
    assert response.status_code == 200
    matches = response.json()
    assert len(matches) == await Match.all().count()

    response = await client.get("/api/matches/search", params={"to_at": "1970-01-01"})
    assert response.status_code == 200
    matches = response.json()
    assert len(matches) == 0
