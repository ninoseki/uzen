from typing import List

import pytest
from fastapi.testclient import TestClient

from app import models


@pytest.mark.usefixtures("snapshots")
def test_whois(
    client: TestClient,
    snapshots: List[models.Snapshot],
):
    id_ = snapshots[0].id
    response = client.get(f"/api/snapshots/{id_}")

    snapshot = response.json()

    whois_id = snapshot.get("whois", {}).get("id", "")
    response = client.get(f"/api/whoises/{whois_id}")
    assert response.status_code == 200
