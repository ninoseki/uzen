import json

import pytest
import respx

from uzen.models.snapshots import Snapshot
from uzen.services.browser import Browser
from uzen.services.classifications import ClassificationBuilder


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan(client):
    payload = {"source": 'rule foo: bar {strings: $a = "foo" condition: $a}'}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 10


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan_with_target(client):
    # it should return all snapshots because every snapshot has "whois" which contains "foo"
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "target": "whois",
    }
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 10

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
async def test_yara_scan_with_invalid_input(client):
    payload = {"source": "boo"}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 500


def mock_take_snapshot(*args, **kwargs):
    return Snapshot(
        url="https://www.w3.org/",
        submitted_url="https://www.w3.org",
        status=200,
        hostname="example.com",
        ip_address="1.1.1.1",
        asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
        server="ECS (sjc/4E5D)",
        content_type="text/html; charset=UTF-8",
        content_length=1256,
        headers={},
        body='<html><body><script type="text/javascript" src="/2008/site/js/main"></body></html>',
        sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
        screenshot="yoyo",
        whois="foo",
        request={},
    )


def mock_take_snapshot_without_script(*args, **kwargs):
    return Snapshot(
        url="https://www.w3.org/",
        submitted_url="https://www.w3.org",
        status=200,
        hostname="example.com",
        ip_address="1.1.1.1",
        asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
        server="ECS (sjc/4E5D)",
        content_type="text/html; charset=UTF-8",
        content_length=1256,
        headers={},
        body="<html><body></body></html>",
        sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
        screenshot="yoyo",
        whois="foo",
        request={},
    )


def mock_build_from_snapshot(snapshot):
    return []


@pytest.mark.asyncio
async def test_yara_oneshot(client, monkeypatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot_without_script)
    monkeypatch.setattr(
        ClassificationBuilder, "build_from_snapshot", mock_build_from_snapshot
    )

    payload = {
        "source": 'rule foo: bar {strings: $a = "body" condition: $a}',
        "url": "https://www.w3.org",
    }
    response = await client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    assert data.get("matched")

    payload = {
        "source": 'rule foo: bar {strings: $a = "foo bar" condition: $a}',
        "url": "https://www.w3.org",
    }
    response = await client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    assert not data.get("matched")


@pytest.mark.asyncio
@respx.mock
async def test_yara_oneshot_with_script(client, monkeypatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)
    monkeypatch.setattr(
        ClassificationBuilder, "build_from_snapshot", mock_build_from_snapshot
    )
    respx.get(
        "https://www.w3.org/2008/site/js/main",
        content='<html><body><script type="text/javascript" src="https://www.w3.org/2008/site/js/main"></body></html>',
    )
    respx.get("https://www.w3.org/2008/site/js/main", content="foo")
    respx.get("http://testserver/*", pass_through=True)

    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "url": "https://www.w3.org",
        "target": "script",
    }
    response = await client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    assert data.get("matched")

    matches = data.get("matches")
    assert isinstance(matches, list)


@pytest.mark.asyncio
async def test_yara_oneshot_with_invalid_input(client):
    # without url
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
    }
    response = await client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 422
