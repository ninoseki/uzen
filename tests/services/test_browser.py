import pytest
from pyppeteer.errors import PyppeteerError

from uzen.services.browser import Browser
from uzen.services.certificate import Certificate
from uzen.services.utils import IPInfo
from uzen.services.whois import Whois


async def mock_get_basic(ip_address: str):
    return {"org": "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"}


def mock_whois(hostname: str):
    return "foo"


def mock_load_and_dump_from_url(url: str):
    return "Certificate:"


@pytest.mark.asyncio
async def test_take_snapshot(monkeypatch):
    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)
    monkeypatch.setattr(Whois, "whois", mock_whois)
    monkeypatch.setattr(
        Certificate, "load_and_dump_from_url", mock_load_and_dump_from_url
    )

    snapshot = await Browser.take_snapshot("http://example.com")
    assert snapshot.url == "http://example.com/"
    assert snapshot.submitted_url == "http://example.com"

    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert snapshot.content_type == "text/html; charset=UTF-8"
    assert (
        snapshot.asn
        == "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"
    )
    assert snapshot.whois == "foo"


@pytest.mark.asyncio
async def test_take_snapshot_with_options(monkeypatch):
    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)
    monkeypatch.setattr(Whois, "whois", mock_whois)

    snapshot = await Browser.take_snapshot("http://example.com", timeout=10000)
    assert snapshot.url == "http://example.com/"

    snapshot = await Browser.take_snapshot("http://example.com", user_agent="foo")
    assert snapshot.url == "http://example.com/"

    snapshot = await Browser.take_snapshot(
        "http://example.com", accept_language="ja-JP"
    )
    assert snapshot.url == "http://example.com/"

    snapshot = await Browser.take_snapshot(
        "http://example.com", timeout=10000, user_agent="foo"
    )
    assert snapshot.url == "http://example.com/"


@pytest.mark.asyncio
async def test_take_snapshot_with_bad_ssl(monkeypatch):
    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)
    monkeypatch.setattr(Whois, "whois", mock_whois)

    with pytest.raises(PyppeteerError):
        snapshot = await Browser.take_snapshot("https://expired.badssl.com")

    snapshot = await Browser.take_snapshot(
        "https://expired.badssl.com", ignore_https_errors=True
    )
    assert snapshot.url == "https://expired.badssl.com/"
