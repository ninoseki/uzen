from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import json
import pytest


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
