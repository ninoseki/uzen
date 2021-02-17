import pytest

from app.factories.domain import DomainFactory


@pytest.mark.asyncio
async def test_build_from_hostname(patch_whois_lookup):
    information = await DomainFactory.from_hostname("example.com")
    assert len(information.dns_records) > 0
