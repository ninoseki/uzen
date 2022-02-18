import socket
from typing import Optional

import pytest
import vcr
from _pytest.monkeypatch import MonkeyPatch

from app.utils.network import (
    get_asn_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)


@vcr.use_cassette("tests/fixtures/vcr_cassettes/ip_address.yaml")
@pytest.mark.asyncio
async def test_get_asn_by_ip_address():
    asn = await get_asn_by_ip_address("93.184.216.34")
    assert asn == "AS15133"


@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("http://example.com", "example.com"),
        ("http://1.1.1.1", "1.1.1.1"),
        ("http://127.0.0.1:8080", "127.0.0.1"),
        ("example.com", None),
    ],
)
def test_get_hostname_from_url(hostname: str, expected: Optional[str]):
    assert get_hostname_from_url(hostname) == expected


def test_get_ip_address_by_hostname(monkeypatch: MonkeyPatch):
    def mockreturn(arg):
        if arg == "one.one.one.one":
            return "1.1.1.1"

    monkeypatch.setattr(socket, "gethostbyname", mockreturn)

    assert get_ip_address_by_hostname("one.one.one.one") == "1.1.1.1"
