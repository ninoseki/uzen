import pytest
import vcr

from uzen.browser import Browser
from uzen.utils import IPInfo
from uzen.whois import Whois
from uzen.certificate import Certificate


def mock_get_basic(ip_address: str):
    return {"org": "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"}


def mock_whois(hostname: str):
    return "foo"


def mock_load_and_dump_from_url(url: str):
    return "Certificate:"


@pytest.mark.asyncio
async def test_take_snapshot(monkeypatch):
    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)
    monkeypatch.setattr(Whois, "whois", mock_whois)
    monkeypatch.setattr(Certificate, "load_and_dump_from_url",
                        mock_load_and_dump_from_url)

    snapshot = await Browser.take_snapshot("http://example.com")
    assert snapshot.url == "http://example.com"
    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert snapshot.content_type == "text/html; charset=UTF-8"
    assert snapshot.asn == "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"
    assert snapshot.whois == "foo"


@pytest.mark.asyncio
async def test_take_snapshot_with_options(monkeypatch):
    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)
    monkeypatch.setattr(Whois, "whois", mock_whois)

    snapshot = await Browser.take_snapshot("http://example.com", timeout=10000)
    assert snapshot.url == "http://example.com"

    snapshot = await Browser.take_snapshot("http://example.com", user_agent="foo")
    assert snapshot.url == "http://example.com"

    snapshot = await Browser.take_snapshot("http://example.com", timeout=10000, user_agent="foo")
    assert snapshot.url == "http://example.com"
