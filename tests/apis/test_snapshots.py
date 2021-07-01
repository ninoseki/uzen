import asyncio

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi.testclient import TestClient

from app.services.browser import Browser
from tests.helper import (
    count_all_snapshots,
    first_snapshot_id_sync,
    make_snapshot_result,
)


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_search(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    count = count_all_snapshots(event_loop)
    response = client.get("/api/snapshots/search")
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = client.get("/api/snapshots/search", params={"hostname": "example.com"})
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = client.get(
        "/api/snapshots/search", params={"from_at": "1970-01-01T15:53:00+05:00"}
    )
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = client.get("/api/snapshots/search", params={"from_at": "1970-01-01"})
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = client.get(
        "/api/snapshots/search", params={"to_at": "3000-01-01T15:53:00+05:00"}
    )
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    # it doesn't match any snapshot
    response = client.get("/api/snapshots/search", params={"status": 404})
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == 0


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_list_with_size(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    payload = {"size": 1}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == 1
    first = snapshots[0]
    assert first.get("url") == "http://example10.com/"


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_list_with_offset_and_size(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    payload = {"offset": 0, "size": 1}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == 1

    offset = 0
    size = 10
    payload = {"offset": offset, "size": size}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == size - offset
    first = snapshots[0]
    assert first.get("url") == f"http://example{size - offset}.com/"

    offset = 5
    size = 100000
    payload = {"offset": offset, "size": size}
    response = client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count_all_snapshots(event_loop) - offset
    first = snapshots[0]
    assert first.get("url") == f"http://example{offset}.com/"


def test_snapshot_post_without_url(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    payload = {}
    response = client.post("/api/snapshots/", json=payload)
    assert response.status_code == 422


def test_snapshot_post_with_invalid_url(client):
    payload = {"url": "foo"}
    response = client.post("/api/snapshots/", json=payload)
    assert response.status_code == 422


def mock_take_snapshot(*args, **kwargs):
    return make_snapshot_result()


def test_snapshot_post(client: TestClient, monkeypatch: MonkeyPatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {"url": "http://example.com"}
    response = client.post("/api/snapshots/", json=payload)

    assert response.status_code == 201

    snapshot = response.json()
    assert snapshot.get("type") == "snapshot"


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_get(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    id_ = first_snapshot_id_sync(event_loop)
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200
    assert response.json().get("id") == str(id_)


@pytest.mark.usefixtures("dns_records_setup")
def test_snapshot_get_with_dns_records(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    id_ = first_snapshot_id_sync(event_loop)
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("dnsRecords")) == 1
    assert len(snapshot.get("scripts")) == 0
    assert len(snapshot.get("classifications")) == 0


@pytest.mark.usefixtures("classifications_setup")
def test_snapshot_get_with_classifications(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    id_ = first_snapshot_id_sync(event_loop)
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("classifications")) == 1
    assert len(snapshot.get("dnsRecords")) == 0
    assert len(snapshot.get("scripts")) == 0


@pytest.mark.usefixtures("scripts_setup")
def test_snapshot_get_with_scripts(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    id_ = first_snapshot_id_sync(event_loop)
    response = client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("scripts")) == 1
    assert len(snapshot.get("classifications")) == 0
    assert len(snapshot.get("dnsRecords")) == 0


@pytest.mark.usefixtures("snapshots_setup")
def test_count(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    count = count_all_snapshots(event_loop)

    response = client.get("/api/snapshots/count")
    assert response.status_code == 200

    data = response.json()
    count_ = data.get("count")
    assert count == count_


@pytest.mark.usefixtures("scripts_setup")
def test_indicators(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    id_ = first_snapshot_id_sync(event_loop)
    response = client.get(f"/api/snapshots/{id_}/indicators")
    assert response.status_code == 200
