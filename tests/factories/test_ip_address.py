from unittest.mock import AsyncMock

import pytest
import vcr

from app.factories.ip_address import IPAddressFactory
from app.services.whois import Whois


@pytest.mark.asyncio
@vcr.use_cassette("tests/fixtures/vcr_cassettes/ip_address.yaml")
async def test_build_from_ip_address(monkeypatch):
    monkeypatch.setattr(Whois, "lookup", AsyncMock(return_value="foo"))

    information = await IPAddressFactory.from_ip_address("93.184.216.34")
    assert str(information.ip_address) == "93.184.216.34"
