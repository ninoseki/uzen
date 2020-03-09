import pytest


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_script_search(client):
    payload = {"snapshot_id": 1}
    response = await client.get("/api/scripts/search", params=payload)
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 1

    payload = {
        "sha256": "fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75"
    }
    response = await client.get("/api/scripts/search", params=payload)
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 10
