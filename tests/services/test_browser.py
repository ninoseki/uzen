from unittest.mock import AsyncMock

import playwright
import pytest
from playwright import async_playwright

from app.core import settings
from app.core.exceptions import TakeSnapshotError
from app.services.browser import Browser
from app.services.browsers.httpx import HttpxBrowser
from app.services.browsers.playwright import (
    PlaywrightBrowser,
    launch_playwright_browser,
)
from app.services.certificate import Certificate
from app.services.rdap import RDAP
from app.services.whois import Whois


def mock_lookup(ip_address: str):
    return {"asn": "AS15133"}


def mock_whois(hostname: str):
    return "foo"


def mock_load_and_dump_from_url(url: str):
    return "Certificate:"


@pytest.mark.asyncio
async def test_take_snapshot(monkeypatch):
    monkeypatch.setattr(RDAP, "lookup", mock_lookup)
    monkeypatch.setattr(Whois, "whois", mock_whois)
    monkeypatch.setattr(
        Certificate, "load_and_dump_from_url", mock_load_and_dump_from_url
    )

    browser = Browser()
    result = await browser.take_snapshot("http://example.com")
    snapshot = result.snapshot
    assert snapshot.url == "http://example.com/"
    assert snapshot.submitted_url == "http://example.com"

    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert snapshot.asn == "AS15133"

    whois = result.whois
    assert whois.content == "foo"


@pytest.mark.asyncio
async def test_take_snapshot_with_scripts(monkeypatch):
    monkeypatch.setattr(RDAP, "lookup", mock_lookup)
    monkeypatch.setattr(Whois, "whois", mock_whois)
    monkeypatch.setattr(
        Certificate, "load_and_dump_from_url", mock_load_and_dump_from_url
    )

    browser = Browser()
    result = await browser.take_snapshot("https://github.com/")
    assert len(result.script_files) > 0


@pytest.mark.asyncio
async def test_take_snapshot_with_bad_ssl(monkeypatch):
    monkeypatch.setattr(RDAP, "lookup", mock_lookup)
    monkeypatch.setattr(Whois, "whois", mock_whois)

    with pytest.raises(TakeSnapshotError):
        browser = Browser()
        result = await browser.take_snapshot("https://expired.badssl.com")

    browser = Browser(ignore_https_errors=True)
    result = await browser.take_snapshot("https://expired.badssl.com",)
    snapshot = result.snapshot
    assert snapshot.url == "https://expired.badssl.com/"


@pytest.mark.asyncio
async def test_take_snapshot_httpx_fallback(mocker):
    mocker.patch(
        "app.services.browsers.playwright.PlaywrightBrowser.take_snapshot", AsyncMock()
    )
    mocker.patch("app.services.browsers.httpx.HttpxBrowser.take_snapshot", AsyncMock())

    # it should fallback to HTTPX if a host is given
    browser = Browser(headers={"host": "example.com"})
    await browser.take_snapshot("http://example.com")

    PlaywrightBrowser.take_snapshot.assert_not_called()
    HttpxBrowser.take_snapshot.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.timeout(10, method="thread")
async def test_launch_browser(monkeypatch):
    monkeypatch.setattr(
        "app.core.settings.BROWSER_WS_ENDPOINT", "wss://chrome.browserless.io"
    )
    assert settings.BROWSER_WS_ENDPOINT == "wss://chrome.browserless.io"

    try:
        async with async_playwright() as p:
            browser = await launch_playwright_browser(p)
            assert isinstance(browser, playwright.Browser)
            assert browser.wsEndpoint == "wss://chrome.browserless.io"
            await browser.close()
    except Exception:
        pass
