import json

import httpx
import pytest

from app.models.snapshot import Snapshot


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan(client: httpx.AsyncClient):
    # it matches with all snapshots
    payload = {"source": 'rule foo: bar {strings: $a = "foo" condition: $a}'}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == await Snapshot.all().count()


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
@pytest.mark.parametrize("size", [1, 5, 10])
async def test_yara_scan_with_size(client: httpx.AsyncClient, size: int):
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
    }
    params = {"size": size}
    response = await client.post(
        "/api/yara/scan", data=json.dumps(payload), params=params
    )
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == size


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan_with_target(client: httpx.AsyncClient):
    # it should return all snapshots because every snapshot has "whois" which contains "foo"
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "target": "whois",
    }
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == await Snapshot.all().count()

    # it should return an empty list because there is no snapshot which has "certificate"
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "target": "certificate",
    }
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 0


@pytest.mark.asyncio
async def test_yara_scan_with_invalid_input(client: httpx.AsyncClient):
    payload = {"source": "boo"}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 422
