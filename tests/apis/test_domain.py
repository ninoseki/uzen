import httpx
import pytest


@pytest.mark.asyncio
@pytest.mark.usefixtures("patch_whois_lookup")
async def test_get(client: httpx.AsyncClient):
    hostname = "example.com"
    response = await client.get(f"/api/domain/{hostname}")
    assert response.status_code == 200

    json = response.json()
    assert json.get("hostname") == hostname

    snapshots = json.get("snapshots", [])
    assert len(snapshots) == 0

    whois = json.get("whois", "")
    assert whois == whois


@pytest.mark.asyncio
async def test_get_with_invalid_input(client: httpx.AsyncClient):
    response = await client.get("/api/domain/1.1.1.1")
    assert response.status_code == 404
