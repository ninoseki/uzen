from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import json
import pytest


from uzen.browser import Browser
from uzen.models import Snapshot


@pytest.mark.asyncio
async def test_snapshot_list(client):
    response = await client.get("/api/snapshots/")
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
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

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10

    response = await client.get("/api/snapshots/search",
                                params={"hostname": "example"})
    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10

    response = await client.get("/api/snapshots/search",
                                params={"server": "ECS"})
    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10

    response = await client.get("/api/snapshots/search",
                                params={"server": "Tomcat"})
    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_list_with_size(client):
    payload = {"size": 1}
    response = await client.get("/api/snapshots/", params=payload)
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 1
    first = snapshots[0]
    assert first.get("url") == "http://example9.com"


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_list_with_offset_and_size(client):
    payload = {"offset": 0, "size": 1}
    response = await client.get("/api/snapshots/", params=payload)
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 1

    payload = {"offset": 0, "size": 10}
    response = await client.get("/api/snapshots/", params=payload)
    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10
    first = snapshots[0]
    assert first.get("url") == "http://example9.com"

    payload = {"offset": 5, "size": 100}
    response = await client.get("/api/snapshots/", params=payload)
    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 5
    first = snapshots[0]
    assert first.get("url") == "http://example4.com"


@pytest.mark.asyncio
async def test_snapshot_post_without_url(client):
    payload = {}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_snapshot_post_with_invalid_url(client):
    payload = {"url": "foo"}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 400


def mock_take_snapshot(url: str):
    return Snapshot(
        url="http://example.com",
        status=200,
        hostname="example.com",
        ip_address="1.1.1.1",
        asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
        server="ECS (sjc/4E5D)",
        content_type="text/html; charset=UTF-8",
        content_length=1256,
        headers={},
        body="foo bar",
        sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
        screenshot="yoyo",
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_post(client, monkeypatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {"url": "http://example.com"}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))

    assert response.status_code == 201

    data = response.json()
    snapshot = data.get("snapshot", {})
    assert snapshot.get("url") == "http://example.com"
    assert snapshot.get("body") == "foo bar"
