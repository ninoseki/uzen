from unittest.mock import AsyncMock

import pytest

from app.factories.domain import DomainFactory
from app.services.whois import Whois


@pytest.mark.asyncio
async def test_build_from_hostname(monkeypatch):
    monkeypatch.setattr(Whois, "lookup", AsyncMock(return_value="foo"))

    information = await DomainFactory.from_hostname("example.com")
    assert len(information.dns_records) > 0
