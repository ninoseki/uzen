from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from app import dataclasses
from app.services.browsers.httpx import HttpxBrowser
from app.services.certificate import Certificate
from app.services.ip2asn import IP2ASN
from app.services.whois import Whois


def mock_whois(hostname: str):
    return "foo"


def mock_load_from_url(url: str):
    return None


@pytest.mark.asyncio
@respx.mock
async def test_take_snapshot(monkeypatch):
    monkeypatch.setattr(IP2ASN, "lookup", AsyncMock(return_value={"asn": "AS15133"}))
    monkeypatch.setattr(Whois, "whois", mock_whois)
    monkeypatch.setattr(Certificate, "load_from_url", mock_load_from_url)
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
