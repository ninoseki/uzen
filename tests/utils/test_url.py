import pytest

from app.utils.url import url_base_form


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://example.com", "https://example.com/"),
        ("https://example.com/", "https://example.com/"),
        ("https://example.com?test=bingo&q=t'", "https://example.com/"),
        ("https://example.com/foo/bar/", "https://example.com/"),
    ],
)
def test_get_hostname_from_url(url: str, expected: str):
    assert url_base_form(url) == expected
