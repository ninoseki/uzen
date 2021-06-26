from unittest.mock import AsyncMock

import pytest
from pytest_mock.plugin import MockerFixture

from app.core.exceptions import TakeSnapshotError
from app.services.browser import Browser
from app.services.browsers.httpx import HttpxBrowser
from app.services.browsers.playwright import PlaywrightBrowser


@pytest.mark.asyncio
@pytest.mark.usefixtures("patch_whois_lookup")
@pytest.mark.usefixtures("patch_ip2asn_lookup")
@pytest.mark.usefixtures("patch_certificate_load_from_url")
async def test_take_snapshot():
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
@pytest.mark.usefixtures("patch_whois_lookup")
@pytest.mark.usefixtures("patch_ip2asn_lookup")
@pytest.mark.usefixtures("patch_certificate_load_from_url")
async def test_take_snapshot_with_scripts():
    browser = Browser()
    result = await browser.take_snapshot("https://github.com/")
    assert len(result.script_files) > 0

    # it should record ip address
    for script_file in result.script_files:
        assert script_file.script.ip_address is not None


@pytest.mark.asyncio
@pytest.mark.usefixtures("patch_whois_lookup")
@pytest.mark.usefixtures("patch_ip2asn_lookup")
async def test_take_snapshot_with_bad_ssl():
    with pytest.raises(TakeSnapshotError):
        browser = Browser()
        result = await browser.take_snapshot("https://expired.badssl.com")

    browser = Browser(ignore_https_errors=True)
    result = await browser.take_snapshot(
        "https://expired.badssl.com",
    )
    snapshot = result.snapshot
    assert snapshot.url == "https://expired.badssl.com/"


@pytest.mark.asyncio
async def test_take_snapshot_httpx_fallback(mocker: MockerFixture):
    mocker.patch(
        "app.services.browsers.playwright.PlaywrightBrowser.take_snapshot", AsyncMock()
    )
    mocker.patch("app.services.browsers.httpx.HttpxBrowser.take_snapshot", AsyncMock())

    # it should fallback to HTTPX if a host is given
    browser = Browser(headers={"host": "example.com"})
    await browser.take_snapshot("http://example.com")

    PlaywrightBrowser.take_snapshot.assert_not_called()
    HttpxBrowser.take_snapshot.assert_called_once()
