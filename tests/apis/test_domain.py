import pytest

from app.services.whois import Whois


def mock_whois(hostname: str):
    return "foo"


@pytest.mark.asyncio
async def test_get(client, monkeypatch):
    monkeypatch.setattr(Whois, "whois", mock_whois)

    hostname = "example.com"
    response = await client.get(f"/api/domain/{hostname}")
    assert response.status_code == 200

    json = response.json()
    assert json.get("hostname") == hostname

    snapshots = json.get("snapshots", [])
    assert len(snapshots) == 0

    whois = json.get("whois", "")
    assert whois == whois
