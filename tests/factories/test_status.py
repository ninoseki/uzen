import pytest
import vcr

from app.factories.status import StatusFactory


@pytest.mark.asyncio
@vcr.use_cassette("tests/fixtures/vcr_cassettes/ipinfo.yaml")
async def test_from_ipifo():
    status = await StatusFactory.from_ipinfo()

    assert str(status.ip_address) == "1.1.1.1"
    assert status.country_code == "AU"
