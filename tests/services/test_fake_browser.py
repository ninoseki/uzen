from pyppeteer.errors import PyppeteerError
import pyppeteer
import pytest
import vcr

from uzen.services.browser import Browser
from uzen.services.certificate import Certificate
from uzen.services.fake_browser import FakeBrowser
from uzen.services.utils import IPInfo
from uzen.services.whois import Whois


def mock_get_basic(ip_address: str):
    return {"org": "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"}


def mock_whois(hostname: str):
    return "foo"


def mock_load_and_dump_from_url(url: str):
    return "Certificate:"


@vcr.use_cassette("tests/fixtures/vcr_cassettes/fake_browser.yaml")
def test_take_snapshot(monkeypatch):
    monkeypatch.setattr(IPInfo, "get_basic", mock_get_basic)
    monkeypatch.setattr(Whois, "whois", mock_whois)
    monkeypatch.setattr(
        Certificate, "load_and_dump_from_url", mock_load_and_dump_from_url
    )

    snapshot = FakeBrowser.take_snapshot("http://example.com")
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
