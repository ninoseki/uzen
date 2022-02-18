import pytest

from app.factories.domain import DomainFactory


@pytest.mark.asyncio
@pytest.mark.usefixtures("patch_whois_lookup")
async def test_build_from_hostname():
    information = await DomainFactory.from_hostname("example.com")
    assert len(information.dns_records) > 0
