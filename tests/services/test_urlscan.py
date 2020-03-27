import datetime
import pathlib

import pytest
import respx

from uzen.services.urlscan import URLScan

path = pathlib.Path(__file__).parent / "../fixtures/urlscan.json"
fixture = open(path, "r").read()


@pytest.mark.asyncio
@respx.mock
async def test_urlscan_import():
    respx.get(
        "https://urlscan.io/api/v1/result/e6d69372-b402-487a-9825-7e25cc15ce41/",
        content=fixture,
    )
    respx.get(
        "https://urlscan.io/dom/e6d69372-b402-487a-9825-7e25cc15ce41/", content="foo"
    )
    respx.get(
        "https://urlscan.io/screenshots/e6d69372-b402-487a-9825-7e25cc15ce41.png",
        content="foo",
    )

    snapshot = await URLScan.import_as_snapshot("e6d69372-b402-487a-9825-7e25cc15ce41")
    assert snapshot.url == "https://nnpub.org/"
    assert snapshot.ip_address == "162.215.240.128"
    assert (
        snapshot.server
        == "Apache/2.4.41 (cPanel) OpenSSL/1.1.1d mod_bwlimited/1.4 Phusion_Passenger/5.3.7"
    )
    assert snapshot.content_type == "text/html; charset=utf-8"
    assert isinstance(snapshot.created_at, datetime.datetime)
