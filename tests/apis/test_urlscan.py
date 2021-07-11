import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi.testclient import TestClient

from app.services.urlscan import URLScan
from tests.helper import make_snapshot_wrapper


def mock_import_as_snapshot(url: str):
    return make_snapshot_wrapper()


@pytest.mark.usefixtures("snapshots_setup")
def test_snapshot_post(client: TestClient, monkeypatch: MonkeyPatch):
    monkeypatch.setattr(URLScan, "import_as_snapshot", mock_import_as_snapshot)

    response = client.post("/api/import/foo")

    assert response.status_code == 201

    data = response.json()
    assert data.get("url") == "http://example.com/"
    assert data.get("html").get("sha256")
