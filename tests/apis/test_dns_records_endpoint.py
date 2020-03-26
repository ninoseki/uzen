import pytest


@pytest.mark.asyncio
@pytest.mark.usefixtures("dns_records_setup")
async def test_dns_record_search(client):
    payload = {"snapshot_id": 1}
    response = await client.get("/api/dns_records/search", params=payload)
    assert response.status_code == 200

    records = response.json()
    assert len(records) == 1

    payload = {"value": "1.1.1.1"}
    response = await client.get("/api/dns_records/search", params=payload)
    assert response.status_code == 200

    records = response.json()
    assert len(records) == 1
