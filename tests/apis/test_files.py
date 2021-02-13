import pytest

from app.models.script import Script


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_files(client):
    first = await Script.all().first()
    sha256 = first.file_id

    response = await client.get(f"/api/files/{sha256}")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_files_404(client):
    response = await client.get("/api/files/404")
    assert response.status_code == 404
