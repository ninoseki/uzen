from typing import List

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi.testclient import TestClient

from app import models
from app.services.browser import Browser
from tests.helper import make_snapshot_wrapper


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"hostname": "example.com"},
        {"from_at": "1970-01-01T15:53:00+05:00"},
        {"fromAt": "1970-01-01T15:53:00+05:00"},
        {"from_at": "1970-01-01"},
        {"to_at": "3000-01-01T15:53:00+05:00"},
        {"toAt": "3000-01-01T15:53:00+05:00"},
    ],
)
def test_snapshot_search(
    client: TestClient, snapshots: List[models.Snapshot], params: dict
):
    count = len(snapshots)
    response = client.get("/api/snapshots/search", params=params)
    data = response.json()
    results = data.get("results", [])
    assert len(results) == count


@pytest.mark.usefixtures("snapshots")
def test_snapshot_list_with_size(
    client: TestClient,
):
    payload = {"size": 1}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    results = data.get("results", [])
    assert len(results) == 1

    first = results[0]
    assert first.get("url") == "http://example10.com/"


def test_snapshot_list_with_offset_and_size(
    client: TestClient,
    snapshots: List[models.Snapshot],
):
    payload = {"offset": 0, "size": 1}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    results = data.get("results", [])
    assert len(results) == 1

    offset = 0
    size = 10
    payload = {"offset": offset, "size": size}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    results = data.get("results", [])
    assert len(results) == size - offset
    first = results[0]
    assert first.get("url") == f"http://example{size - offset}.com/"

    offset = 5
    size = 100000
    payload = {"offset": offset, "size": size}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    results = data.get("results", [])
    assert len(results) == len(snapshots) - offset
    first = results[0]
    assert first.get("url") == f"http://example{offset}.com/"


def test_snapshot_post_without_url(client: TestClient):
    payload = {}
    response = client.post("/api/snapshots/", json=payload)
    assert response.status_code == 422


def test_snapshot_post_with_invalid_url(client):
    payload = {"url": "foo"}
    response = client.post("/api/snapshots/", json=payload)
    assert response.status_code == 422


def mock_take_snapshot(*args, **kwargs):
    return make_snapshot_wrapper()


def test_snapshot_post(client: TestClient, monkeypatch: MonkeyPatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {"url": "http://example.com"}
    response = client.post("/api/snapshots/", json=payload)

    assert response.status_code == 201

    snapshot = response.json()
    assert snapshot.get("type") == "snapshot"


@pytest.mark.usefixtures("snapshots")
def test_snapshot_get(
    client: TestClient,
    snapshots: List[models.Snapshot],
):
    id_ = snapshots[0].id
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200
    assert response.json().get("id") == str(id_)


@pytest.mark.usefixtures("dns_records")
def test_snapshot_get_with_dns_records(
    client: TestClient,
    snapshots: List[models.Snapshot],
):
    id_ = snapshots[0].id
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("dnsRecords")) == 1
    assert len(snapshot.get("scripts")) == 0
    assert len(snapshot.get("classifications")) == 0


@pytest.mark.usefixtures("classifications")
def test_snapshot_get_with_classifications(
    client: TestClient,
    snapshots: List[models.Snapshot],
):
    id_ = snapshots[0].id
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("classifications")) == 1
    assert len(snapshot.get("dnsRecords")) == 0
    assert len(snapshot.get("scripts")) == 0


@pytest.mark.usefixtures("scripts")
def test_snapshot_get_with_scripts(
    client: TestClient, snapshots: List[models.Snapshot]
):
    id_ = snapshots[0].id
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("scripts")) == 1
    assert len(snapshot.get("classifications")) == 0
    assert len(snapshot.get("dnsRecords")) == 0


def test_count(
    client: TestClient,
    snapshots: List[models.Snapshot],
):
    count = len(snapshots)

    response = client.get("/api/snapshots/count")
    assert response.status_code == 200

    data = response.json()
    count_ = data.get("count")
    assert count == count_


@pytest.mark.usefixtures("scripts")
def test_indicators(
    client: TestClient,
    snapshots: List[models.Snapshot],
):
    id_ = snapshots[0].id
    response = client.get(f"/api/snapshots/{id_}/indicators")
    assert response.status_code == 200
