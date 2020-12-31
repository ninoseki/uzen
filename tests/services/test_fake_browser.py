import pytest
import respx
from httpx import Response

from uzen.services.certificate import Certificate
from uzen.services.fake_browser import FakeBrowser
from uzen.services.rdap import RDAP
from uzen.services.whois import Whois


def mock_lookup(ip_address: str):
    return {"asn": "AS15133"}


def mock_whois(hostname: str):
    return "foo"


def mock_load_and_dump_from_url(url: str):
    return "Certificate:"


@pytest.mark.asyncio
@respx.mock
async def test_take_snapshot(monkeypatch):
    monkeypatch.setattr(RDAP, "lookup", mock_lookup)
    monkeypatch.setattr(Whois, "whois", mock_whois)
    monkeypatch.setattr(
        Certificate, "load_and_dump_from_url", mock_load_and_dump_from_url
    )
    respx.get("http://example.com/",).mock(
        Response(status_code=200, content="foo", headers={"Content-Type": "text/html"})
    )

    result = await FakeBrowser.take_snapshot("http://example.com")
    snapshot = result.snapshot
    assert snapshot.url == "http://example.com"
    assert snapshot.submitted_url == "http://example.com"

    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert "text/html" in snapshot.content_type
    assert snapshot.asn == "AS15133"
    assert snapshot.whois == "foo"
