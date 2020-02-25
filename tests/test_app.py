from starlette.responses import HTMLResponse
from starlette.testclient import TestClient
import pytest
import json


def test_app(client):
    response = client.get("/")
    assert response.status_code == 200

    response = client.get("/foo")
    assert response.status_code == 404
