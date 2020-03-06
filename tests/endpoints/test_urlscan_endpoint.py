from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import json
import pytest
import datetime

from uzen.urlscan import URLScan
from uzen.models import Snapshot
from tests.utils import make_snapshot


def mock_import_as_snapshot(url: str):
    return make_snapshot()


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
