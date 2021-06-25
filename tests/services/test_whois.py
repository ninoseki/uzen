import pytest

from app.services.whois import Whois, convert_hostname


@pytest.mark.asyncio
async def test_lookup_cached() -> None:
    res = await Whois.lookup("example.com")
    if res is not None:
        assert res.content is not None


@pytest.mark.parametrize(
    "test_input,expected",
    [("1.1.1.1", "1.1.1.1"), ("www.example.com", "example.com")],
)
def test_convert_hostname(test_input: str, expected: str):
    assert convert_hostname(test_input) == expected
