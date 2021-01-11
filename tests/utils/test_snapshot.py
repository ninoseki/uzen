from unittest.mock import AsyncMock

import pytest

from app.services.browser import Browser
from app.services.fake_browser import FakeBrowser
from app.utils.snapshot import take_snapshot


@pytest.mark.asyncio
async def test_take_snapshot(mocker):
    mocker.patch("app.services.browser.Browser.take_snapshot", AsyncMock())
    mocker.patch("app.services.fake_browser.FakeBrowser.take_snapshot", AsyncMock())

    # it should fallback to HTTPX if a host is given
    await take_snapshot(url="http://example.com", host="example.com")

    Browser.take_snapshot.assert_not_called()
    FakeBrowser.take_snapshot.assert_called_once()


@pytest.mark.asyncio
async def test_take_snapshot_2(mocker, monkeypatch):
    monkeypatch.setattr("app.core.settings.HTTPX_FALLBACK", False)
    mocker.patch("app.services.browser.Browser.take_snapshot", AsyncMock())
    mocker.patch("app.services.fake_browser.FakeBrowser.take_snapshot", AsyncMock())

    # it should use HTTPX even if HTTPX_FALLBACK is false
    await take_snapshot(url="http://example.com", host="example.com")

    Browser.take_snapshot.assert_not_called()
    FakeBrowser.take_snapshot.assert_called_once()
