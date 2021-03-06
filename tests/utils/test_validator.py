import pytest

from app.utils.validator import is_domain, is_ip_address


@pytest.mark.parametrize(
    "ip_address,expected",
    [
        ("foo", False),
        ("example.com", False),
        ("1.1.1.1", True),
        ("127.0.0.1", True),
    ],
)
def test_is_ip_address(ip_address: str, expected: bool):
    assert is_ip_address(ip_address) is expected


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("foo", False),
        ("example.com", True),
        ("1.1.1.1", False),
        ("127.0.0.1", False),
    ],
)
def test_is_domain(domain: str, expected: bool):
    assert is_domain(domain) is expected
