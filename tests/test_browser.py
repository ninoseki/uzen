import pytest

from uzen.browser import Browser


@pytest.mark.asyncio
async def test_take_snapshot():
    snapshot = await Browser.take_snapshot("http://example.com")

    assert snapshot.url == "http://example.com"
    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert snapshot.content_type == "text/html; charset=UTF-8"
