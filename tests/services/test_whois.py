import pytest

from app.services.whois import Whois


@pytest.mark.asyncio
async def test_lookup_cached() -> None:
    res = await Whois.lookup("example.com")
    if res is not None:
        assert res.content is not None
