import pytest


@pytest.mark.asyncio
async def test_get(client, patch_whois_lookup):
    hostname = "example.com"
    response = await client.get(f"/api/domain/{hostname}")
    assert response.status_code == 200

    json = response.json()
    assert json.get("hostname") == hostname

    snapshots = json.get("snapshots", [])
    assert len(snapshots) == 0

    whois = json.get("whois", "")
    assert whois == whois
