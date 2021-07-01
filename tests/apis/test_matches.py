import asyncio

import pytest
from fastapi.testclient import TestClient

from tests.helper import count_all_matches, first_rule_id_sync, first_snapshot_id_sync


@pytest.mark.usefixtures("matches_setup")
def test_matches_search(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    count = count_all_matches(event_loop)

    response = client.get("/api/matches/search")
    assert response.status_code == 200

    data = response.json()
    matches = data.get("results")
    assert len(matches) == count

    first = matches[0]
    assert isinstance(first.get("snapshot"), dict)
    assert isinstance(first.get("rule"), dict)

    total = data.get("total")
    assert total == count


@pytest.mark.usefixtures("matches_setup")
def test_matches_search_with_filters(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    snapshot_id = first_snapshot_id_sync(event_loop)
    response = client.get("/api/matches/search", params={"snapshot_id": snapshot_id})
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 1

    rule_id = first_rule_id_sync(event_loop)
    response = client.get("/api/matches/search", params={"rule_id": rule_id})
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 1

    response = client.get(
        "/api/matches/search", params={"rule_id": rule_id, "snapshot_id": snapshot_id}
    )
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 1


@pytest.mark.usefixtures("matches_setup")
def test_matches_search_with_daterange(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    response = client.get("/api/matches/search", params={"from_at": "1970-01-01"})
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == count_all_matches(event_loop)

    response = client.get("/api/matches/search", params={"to_at": "1970-01-01"})
    assert response.status_code == 200
    data = response.json()
    matches = data.get("results")
    assert len(matches) == 0
