import socket

import pytest
import respx

from uzen.services.utils import (
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)


@pytest.mark.asyncio
@respx.mock
async def test_get_asn_by_ip_address():
    respx.get(
        "https://ipinfo.io/1.1.1.1/json", content='{"org": "AS13335 Cloudflare, Inc."}'
    )
    res = await get_asn_by_ip_address("1.1.1.1")
    assert res == "AS13335 Cloudflare, Inc."


@pytest.mark.parametrize(
    "hostname,expected",
    [
        pytest.param("http://example.com", "example.com"),
        pytest.param("http://1.1.1.1", "1.1.1.1"),
        pytest.param("http://127.0.0.1:8080", "127.0.0.1"),
        pytest.param("example.com", None),
    ],
)
def test_get_hostname_from_url(hostname, expected):
    assert get_hostname_from_url(hostname) == expected


def test_get_ip_address_by_hostname(monkeypatch):
    def mockreturn(arg):
        if arg == "one.one.one.one":
            return "1.1.1.1"

    monkeypatch.setattr(socket, "gethostbyname", mockreturn)

    assert get_ip_address_by_hostname("one.one.one.one") == "1.1.1.1"
