import pytest

from app.utils.validator import is_asn, is_domain, is_hash, is_ip_address


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


@pytest.mark.parametrize(
    "asn,expected",
    [
        ("foo", False),
        ("ASB", False),
        ("AS1B", False),
        ("AS1", True),
        ("AS123", True),
    ],
)
def test_is_asn(asn: str, expected: bool):
    assert is_asn(asn) is expected


@pytest.mark.parametrize(
    "hash,expected",
    [
        ("foo", False),
        ("c768d548eb0443abc9e15c1e8a833ebd2200e755c97e31dfe1ab67f5e2df6eff1", False),
        ("c768d548eb0443abc9e15c1e8a833ebd2200e755c97e31dfe1ab67f5e2df6ef", False),
        ("c768d548eb0443abc9e15c1e8a833ebd2200e755c97e31dfe1ab67f5e2df6eff", True),
    ],
)
def test_is_hash(hash: str, expected: bool):
    assert is_hash(hash) is expected
