import pytest
import vcr

from uzen.factories.ip_address import IPAddressInformationFactory
from uzen.services.whois import Whois


def mock_whois(hostname: str):
    return "foo"


@pytest.mark.asyncio
@vcr.use_cassette("tests/fixtures/vcr_cassettes/ip_address.yaml")
async def test_build_from_ip_address(monkeypatch):
    monkeypatch.setattr(Whois, "whois", mock_whois)

    information = await IPAddressInformationFactory.from_ip_address("1.1.1.1")
    assert str(information.ip_address) == "1.1.1.1"
