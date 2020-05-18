import pytest

from uzen.factories.domain import DomainInformationFactory
from uzen.services.whois import Whois


def mock_whois(hostname: str):
    return "foo"


@pytest.mark.asyncio
async def test_build_from_hostname(monkeypatch):
    monkeypatch.setattr(Whois, "whois", mock_whois)

    information = await DomainInformationFactory.from_hostname("example.com")
    assert len(information.dns_records) > 0
