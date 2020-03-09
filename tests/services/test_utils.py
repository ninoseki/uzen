import socket

import pytest
import vcr

from uzen.services.utils import (
    get_country_code_by_ip_address,
    get_hostname_from_url,
    get_ip_address_by_hostname,
)


@vcr.use_cassette("tests/fixtures/vcr_cassettes/get_country_code_by_ip_address.yaml")
def test_get_country_code_by_ip_address():
    assert get_country_code_by_ip_address("1.1.1.1") == "AU"


@pytest.mark.parametrize(
    "hostname,expected",
    [
        pytest.param("http://example.com", "example.com"),
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
