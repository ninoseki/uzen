import pytest

from uzen.services.browser import Browser
from uzen.services.fake_browser import FakeBrowser
from uzen.services.snapshot import take_snapshot


@pytest.mark.asyncio
async def test_take_snapshot(mocker):
    mocker.patch("uzen.services.browser.Browser.take_snapshot")
    mocker.patch("uzen.services.fake_browser.FakeBrowser.take_snapshot")

    # it should fallback to HTTPX if a host is given
    await take_snapshot(url="http://example.com", host="example.com")

    Browser.take_snapshot.assert_not_called()
    FakeBrowser.take_snapshot.assert_called_once()


@pytest.mark.asyncio
async def test_take_snapshot_2(mocker, monkeypatch):
    monkeypatch.setattr("uzen.core.settings.ENABLE_HTTPX_FALLBACK", False)
    mocker.patch("uzen.services.browser.Browser.take_snapshot")
    mocker.patch("uzen.services.fake_browser.FakeBrowser.take_snapshot")

    # it should use HTTPX even if ENABLE_HTTPX_FALLBACK is false
    await take_snapshot(url="http://example.com", host="example.com")

    Browser.take_snapshot.assert_not_called()
    FakeBrowser.take_snapshot.assert_called_once()
