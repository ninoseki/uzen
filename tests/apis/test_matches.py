import asyncio
from typing import List

import pytest
from fastapi.testclient import TestClient

from app import models
from tests.helper import count_all_matches


@pytest.mark.usefixtures("matches")
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


def test_matches_search_with_filters(
    client: TestClient,
    matches: List[models.Match],
    snapshots: List[models.Snapshot],
    rules: List[models.Rule],
):
    snapshot_id = snapshots[0].id
    response = client.get("/api/matches/search", params={"snapshotId": snapshot_id})
    assert response.status_code == 200
    data = response.json()
    results = data.get("results", [])
    assert len(results) == 1

    rule_id = rules[0].id
    response = client.get("/api/matches/search", params={"ruleId": rule_id})
    assert response.status_code == 200
    data = response.json()
    results = data.get("results", [])
    assert len(results) == 1

    response = client.get(
        "/api/matches/search", params={"ruleId": rule_id, "snapshotId": snapshot_id}
    )
    assert response.status_code == 200
    data = response.json()
    results = data.get("results", [])
    assert len(results) == 1


def test_matches_search_with_daterange(
    client: TestClient,
    event_loop: asyncio.AbstractEventLoop,
    matches: List[models.Match],
):
    response = client.get("/api/matches/search", params={"fromAt": "1970-01-01"})
    assert response.status_code == 200
    data = response.json()
    results = data.get("results", [])
    assert len(results) == count_all_matches(event_loop)

    response = client.get("/api/matches/search", params={"toAt": "1970-01-01"})
    assert response.status_code == 200
    data = response.json()
    results = data.get("results", [])
    assert len(results) == 0
