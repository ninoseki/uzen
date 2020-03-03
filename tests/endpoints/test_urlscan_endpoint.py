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
    monkeypatch.setattr(URLScan, "import_as_snapshot", mock_import_as_snapshot)

    response = await client.post("/api/import/foo")

    assert response.status_code == 201

    data = response.json()
    snapshot = data.get("snapshot", {})
    assert snapshot.get("url") == "http://example.com"
    assert snapshot.get("body") == "foo bar"
