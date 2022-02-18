import pytest
import vcr

from app.factories.ip_address import IPAddressFactory


@pytest.mark.asyncio
@vcr.use_cassette("tests/fixtures/vcr_cassettes/ip_address.yaml")
@pytest.mark.usefixtures("patch_whois_lookup")
async def test_build_from_ip_address():
    information = await IPAddressFactory.from_ip_address("93.184.216.34")
    assert str(information.ip_address) == "93.184.216.34"
