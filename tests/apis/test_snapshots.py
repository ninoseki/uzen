import json

import httpx
import pytest
from _pytest.monkeypatch import MonkeyPatch

from app.models.snapshot import Snapshot
from app.services.browser import Browser
from tests.helper import first_snapshot_id, make_snapshot_result


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_search(client: httpx.AsyncClient):
    count = await Snapshot.all().count()
    response = await client.get("/api/snapshots/search")
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = await client.get(
        "/api/snapshots/search", params={"hostname": "example.com"}
    )
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = await client.get(
        "/api/snapshots/search", params={"from_at": "1970-01-01T15:53:00+05:00"}
    )
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = await client.get(
        "/api/snapshots/search", params={"from_at": "1970-01-01"}
    )
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    response = await client.get(
        "/api/snapshots/search", params={"to_at": "3000-01-01T15:53:00+05:00"}
    )
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == count

    # it doesn't match any snapshot
    response = await client.get("/api/snapshots/search", params={"status": 404})
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_list_with_size(client: httpx.AsyncClient):
    payload = {"size": 1}
    response = await client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == 1
    first = snapshots[0]
    assert first.get("url") == "http://example10.com/"


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_list_with_offset_and_size(client: httpx.AsyncClient):
    payload = {"offset": 0, "size": 1}
    response = await client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == 1

    offset = 0
    size = 10
    payload = {"offset": offset, "size": size}
    response = await client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == size - offset
    first = snapshots[0]
    assert first.get("url") == f"http://example{size - offset}.com/"

    offset = 5
    size = 100000
    payload = {"offset": offset, "size": size}
    response = await client.get("/api/snapshots/search", params=payload)
    data = response.json()
    snapshots = data.get("results")
    assert len(snapshots) == await Snapshot.all().count() - offset
    first = snapshots[0]
    assert first.get("url") == f"http://example{offset}.com/"


@pytest.mark.asyncio
async def test_snapshot_post_without_url(client: httpx.AsyncClient):
    payload = {}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_snapshot_post_with_invalid_url(client):
    payload = {"url": "foo"}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))
    assert response.status_code == 422


def mock_take_snapshot(*args, **kwargs):
    return make_snapshot_result()


@pytest.mark.asyncio
async def test_snapshot_post(client: httpx.AsyncClient, monkeypatch: MonkeyPatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {"url": "http://example.com"}
    response = await client.post("/api/snapshots/", data=json.dumps(payload))

    assert response.status_code == 201

    snapshot = response.json()
    assert snapshot.get("type") == "snapshot"


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_get(client: httpx.AsyncClient):
    id_ = await first_snapshot_id()
    response = await client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200
    assert response.json().get("id") == str(id_)


@pytest.mark.asyncio
@pytest.mark.usefixtures("dns_records_setup")
async def test_snapshot_get_with_dns_records(client: httpx.AsyncClient):
    id_ = await first_snapshot_id()
    response = await client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("dnsRecords")) == 1
    assert len(snapshot.get("scripts")) == 0
    assert len(snapshot.get("classifications")) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("classifications_setup")
async def test_snapshot_get_with_classifications(client: httpx.AsyncClient):
    id_ = await first_snapshot_id()
    response = await client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("classifications")) == 1
    assert len(snapshot.get("dnsRecords")) == 0
    assert len(snapshot.get("scripts")) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_snapshot_get_with_scripts(client: httpx.AsyncClient):
    id_ = await first_snapshot_id()
    response = await client.get(f"/api/snapshots/{id_}")
    assert response.status_code == 200

    snapshot = response.json()
    assert len(snapshot.get("scripts")) == 1
    assert len(snapshot.get("classifications")) == 0
    assert len(snapshot.get("dnsRecords")) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_count(client: httpx.AsyncClient):
    count = await Snapshot.all().count()

    response = await client.get("/api/snapshots/count")
    assert response.status_code == 200

    data = response.json()
    count_ = data.get("count")
    assert count == count_
