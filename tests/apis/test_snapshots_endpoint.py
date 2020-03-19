import json

import pytest

from tests.utils import make_snapshot
from uzen.models.snapshots import Snapshot
from uzen.services.browser import Browser


@pytest.mark.asyncio
async def test_snapshot_list(client):
    response = await client.get("/api/snapshots/")
    assert response.status_code == 200

    snapshots = response.json()
    assert isinstance(snapshots, list)


@pytest.mark.asyncio
async def test_snapshot_count(client):
    response = await client.get("/api/snapshots/count")
    assert response.status_code == 200

    data = response.json()
    count = data.get("count")
    assert isinstance(count, int)


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_search(client):
    response = await client.get("/api/snapshots/search")
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 10

    response = await client.get("/api/snapshots/search", params={"hostname": "example"})
    snapshots = response.json()
    assert len(snapshots) == 10

    response = await client.get("/api/snapshots/search", params={"server": "ECS"})
    snapshots = response.json()
    assert len(snapshots) == 10

    response = await client.get("/api/snapshots/search", params={"server": "Tomcat"})
    snapshots = response.json()
    assert len(snapshots) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_list_with_size(client):
    payload = {"size": 1}
    response = await client.get("/api/snapshots/", params=payload)
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 1
    first = snapshots[0]
    assert first.get("url") == "http://example9.com/"


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_list_with_offset_and_size(client):
    payload = {"offset": 0, "size": 1}
    response = await client.get("/api/snapshots/", params=payload)
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 1

    payload = {"offset": 0, "size": 10}
    response = await client.get("/api/snapshots/", params=payload)
    snapshots = response.json()
    assert len(snapshots) == 10
    first = snapshots[0]
    assert first.get("url") == "http://example9.com/"

    payload = {"offset": 5, "size": 100}
    response = await client.get("/api/snapshots/", params=payload)
    snapshots = response.json()
    assert len(snapshots) == 5
    first = snapshots[0]
    assert first.get("url") == "http://example4.com/"


@pytest.mark.asyncio
async def test_snapshot_post_without_url(client):
    payload = {}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_snapshot_post_with_invalid_url(client):
    payload = {"url": "foo"}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 422


def mock_take_snapshot(
    url: str,
    user_agent: None,
    accept_language: None,
    timeout: None,
    ignore_https_errors: False,
):
    return make_snapshot()


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_post(client, monkeypatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {"url": "http://example.com"}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))

    assert response.status_code == 201

    snapshot = response.json()
    assert snapshot.get("url") == "http://example.com/"
    assert snapshot.get("body") == "foo bar"

    snapshot = await Snapshot.get(id=snapshot.get("id"))
    await snapshot.fetch_related("scripts")
    assert len(snapshot.scripts) == 0
