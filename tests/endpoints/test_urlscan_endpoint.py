from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import json
import pytest


from uzen.urlscan import URLScan
from uzen.models import Snapshot


def mock_import_as_snapshot(url: str):
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
    monkeypatch.setattr(URLScan, "import_as_snapshot", mock_import_as_snapshot)

    response = client.post("/api/import/foo")

    assert response.status_code == 201

    data = response.json()
    snapshot = data.get("snapshot", {})
    assert snapshot.get("url") == "http://example.com"
    assert snapshot.get("body") == "foo bar"
