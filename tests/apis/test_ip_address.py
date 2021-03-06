import httpx
import pytest
import vcr


@pytest.mark.asyncio
@vcr.use_cassette(
    "tests/fixtures/vcr_cassettes/ip_address.yaml", ignore_hosts=["testserver"]
)
async def test_get(client: httpx.AsyncClient, patch_whois_lookup):
    ip_address = "93.184.216.34"
    response = await client.get(f"/api/ip_address/{ip_address}")
    assert response.status_code == 200

    json = response.json()
    ip_address_ = json.get("ipAddress", "")
    assert ip_address_ == ip_address

    snapshots = json.get("snapshots", [])
    assert len(snapshots) == 0

    whois = json.get("whois", "")
    assert whois == whois


@pytest.mark.asyncio
async def test_get_with_invalid_input(client: httpx.AsyncClient):
    response = await client.get("/api/ip_address/example.com")
    assert response.status_code == 404
