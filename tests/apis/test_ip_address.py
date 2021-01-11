import pytest
import vcr

from app.services.whois import Whois


def mock_whois(hostname: str):
    return "foo"


@pytest.mark.asyncio
@vcr.use_cassette(
    "tests/fixtures/vcr_cassettes/ip_address.yaml", ignore_hosts=["testserver"]
)
async def test_get(client, monkeypatch):
    monkeypatch.setattr(Whois, "whois", mock_whois)

    ip_address = "1.1.1.1"
    response = await client.get(f"/api/ip_address/{ip_address}")
    assert response.status_code == 200

    json = response.json()
    ip_address_ = json.get("ipAddress", "")
    assert ip_address_ == ip_address

    snapshots = json.get("snapshots", [])
    assert len(snapshots) == 0

    whois = json.get("whois", "")
    assert whois == whois
