from typing import List

from fastapi.testclient import TestClient

from app import models


def test_html(client: TestClient, snapshots: List[models.Snapshot]):
    id_ = snapshots[0].id

    response = client.get(f"/api/snapshots/{id_}")
    snapshot = response.json()

    sha256 = snapshot.get("html", {}).get("sha256", "")
    response = client.get(f"/api/htmls/{sha256}")
    assert response.status_code == 200

    sha256 = snapshot.get("html", {}).get("sha256", "")
    response = client.get(f"/api/htmls/{sha256}/text")
    assert response.status_code == 200
