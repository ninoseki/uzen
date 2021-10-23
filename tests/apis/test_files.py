import asyncio

import pytest
from fastapi.testclient import TestClient

from app.models.script import Script


@pytest.mark.usefixtures("scripts")
def test_files(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    first = event_loop.run_until_complete(Script.all().first())
    sha256 = first.file_id

    response = client.get(f"/api/files/{sha256}")
    assert response.status_code == 200


def test_files_404(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    response = client.get("/api/files/404")
    assert response.status_code == 404
