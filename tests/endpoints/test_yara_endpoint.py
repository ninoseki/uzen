from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import json
import pytest

from uzen.browser import Browser
from uzen.models import Snapshot


@pytest.mark.usefixtures("snapshots_setup")
def test_yara_scan(client):
    payload = {"source": 'rule foo: bar {strings: $a = "foo" condition: $a}'}
    response = client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    snapshots = data.get("snapshots")
    assert len(snapshots) == 10


def test_yara_scan_with_invalid_input(client):
    payload = {"source": "boo"}
    response = client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 500


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


def test_yara_oneshot(client, monkeypatch):
    monkeypatch.setattr(Browser, "take_snapshot", mock_take_snapshot)

    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "url": 'http://example.com'
    }
    response = client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    assert data.get("matched") == True

    payload = {
        "source": 'rule foo: bar {strings: $a = "aaa" condition: $a}',
        "url": 'http://example.com'
    }
    response = client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 200

    data = response.json()
    assert data.get("matched") == False


def test_yara_oneshot_with_invalid_input(client):
    # without url
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
    }
    response = client.post("/api/yara/oneshot", data=json.dumps(payload))
    assert response.status_code == 400
