import pytest
import vcr

from uzen.browser import Browser
from uzen.utils import IPInfo
from uzen.whois import Whois


@pytest.mark.asyncio
async def test_take_snapshot(monkeypatch):
    def mock_get_basic(ip_address: str):
        return {"org": "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"}

    def mock_whois(hostname: str):
        return "foo"

    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)
    monkeypatch.setattr(Whois, "whois", mock_whois)

    snapshot = await Browser.take_snapshot("http://example.com")

    assert snapshot.url == "http://example.com"
    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert snapshot.content_type == "text/html; charset=UTF-8"
    assert snapshot.asn == "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"
    assert snapshot.whois == "foo"
