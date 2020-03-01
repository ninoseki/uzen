import pytest
import vcr

from uzen.browser import Browser
from uzen.utils import IPInfo


@pytest.mark.asyncio
async def test_take_snapshot(monkeypatch):
    def mock_get_basic(ip_address: str):
        return {"org": "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"}

    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)

    snapshot = await Browser.take_snapshot("http://example.com")

    assert snapshot.url == "http://example.com"
    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert snapshot.content_type == "text/html; charset=UTF-8"
    assert snapshot.asn == "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"
