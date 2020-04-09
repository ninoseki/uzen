import pytest


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_matches_search(client):
    response = await client.get("/api/matches/search")
    assert response.status_code == 200

    matches = response.json()
    assert len(matches) == 5

    first = matches[0]
    assert isinstance(first.get("snapshot"), dict)
    assert isinstance(first.get("rule"), dict)
