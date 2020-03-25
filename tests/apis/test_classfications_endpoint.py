import pytest


@pytest.mark.asyncio
@pytest.mark.usefixtures("classifications_setup")
async def test_dns_record_search(client):
    payload = {"snapshot_id": 1, "foo": "bar"}
    response = await client.get("/api/classifications/search", params=payload)
    assert response.status_code == 200

    classifications = response.json()
    assert len(classifications) == 1
