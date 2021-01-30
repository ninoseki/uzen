import pytest
import respx
from httpx import Response

from app import dataclasses
from app.services.browsers.httpx import HttpxBrowser
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

    options = dataclasses.BrowsingOptions()
    result = await HttpxBrowser.take_snapshot("http://example.com", options)
    snapshot = result.snapshot
    assert snapshot.url == "http://example.com"
    assert snapshot.submitted_url == "http://example.com"

    assert snapshot.hostname == "example.com"
    assert snapshot.status == 200
    assert snapshot.asn == "AS15133"

    whois = result.whois
    assert whois.content == "foo"
