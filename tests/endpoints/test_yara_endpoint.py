from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import json
import pytest
import datetime

from uzen.browser import Browser
from uzen.models import Snapshot
from tests.utils import make_snapshot


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan(client):
    payload = {"source": 'rule foo: bar {strings: $a = "foo" condition: $a}'}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan_with_target(client):
    # it should return all snapshots because every snapshot has "whois" which contains "foo"
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "target": "whois"
    }
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10

    # it should return an empty list because there is no snapshot which has "certificate"
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "target": "certificate"
    }
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 0


@pytest.mark.asyncio
async def test_yara_scan_with_invalid_input(client):
    payload = {"source": "boo"}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 500


def mock_take_snapshot(url: str):
    return make_snapshot()


@pytest.mark.asyncio
async def test_yara_oneshot(client, monkeypatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "url": 'http://example.com'
    }
    response = await client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    assert data.get("matched") == True

    payload = {
        "source": 'rule foo: bar {strings: $a = "aaa" condition: $a}',
        "url": 'http://example.com'
    }
    response = await client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    assert data.get("matched") == False


@pytest.mark.asyncio
async def test_yara_oneshot_with_invalid_input(client):
    # without url
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
    }
    response = await client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 400
