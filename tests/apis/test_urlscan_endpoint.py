import pytest

from tests.utils import make_snapshot
from uzen.services.urlscan import URLScan


def mock_import_as_snapshot(url: str):
    return make_snapshot()


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_snapshot_post(client, monkeypatch):
    monkeypatch.setattr(URLScan, "import_as_snapshot", mock_import_as_snapshot)

    response = await client.post("/api/import/foo")

    assert response.status_code == 201

    data = response.json()
    assert data.get("url") == "http://example.com"
    assert data.get("body") == "foo bar"
