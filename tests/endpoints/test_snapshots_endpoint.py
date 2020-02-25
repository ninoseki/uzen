from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import json
import pytest


from uzen.browser import Browser
from uzen.models import Snapshot


def test_snapshot_list(client):
    response = client.get("/api/snapshots/")
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert isinstance(snapshots, list)


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_list_with_size(client):
    payload = {"size": 1}
    response = client.get("/api/snapshots/", params=payload)
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 1
    first = snapshots[0]
    assert first.get("url") == "http://example9.com"


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_list_with_offset_and_size(client):
    payload = {"offset": 0, "size": 1}
    response = client.get("/api/snapshots/", params=payload)
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 1

    payload = {"offset": 0, "size": 10}
    response = client.get("/api/snapshots/", params=payload)
    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10
    first = snapshots[0]
    assert first.get("url") == "http://example0.com"

    payload = {"offset": 5, "size": 100}
    response = client.get("/api/snapshots/", params=payload)
    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 5
    first = snapshots[0]
    assert first.get("url") == "http://example5.com"


def test_snapshot_post_without_url(client):
    payload = {}
    response = client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 400


def test_snapshot_post_with_invalid_url(client):
    payload = {"url": "foo"}
    response = client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 400


def mock_take_snapshot(url: str):
    return Snapshot(
        url="http://example.com",
        status=200,
        hostname="example.com",
        ip_address="1.1.1.1",
        server="ECS (sjc/4E5D)",
        content_type="text/html; charset=UTF-8",
        content_length=1256,
        headers={},
        body="foo bar",
        screenshot="yoyo",
    )


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_post(client, monkeypatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {"url": "http://example.com"}
    response = client.post("/api/snapshots/", data=json.dumps(payload))

    assert response.status_code == 201

    data = response.json()
    snapshot = data.get("snapshot", {})
    assert snapshot.get("url") == "http://example.com"
    assert snapshot.get("body") == "foo bar"
