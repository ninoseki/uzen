from typing import List

from fastapi.testclient import TestClient

from app import models


def test_har(client: TestClient, snapshots: List[models.Snapshot]):
    snapshot_id = snapshots[0].id

    response = client.get(f"/api/hars/{snapshot_id}")
    assert response.status_code == 200
