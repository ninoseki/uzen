import pytest
import respx
from httpx import Response

from app import dataclasses
from app.services.browsers.httpx import HttpxBrowser


@pytest.mark.asyncio
@respx.mock
@pytest.mark.usefixtures("patch_whois_lookup")
@pytest.mark.usefixtures("patch_ip2asn_lookup")
@pytest.mark.usefixtures("patch_certificate_load_from_url")
async def test_take_snapshot():
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
