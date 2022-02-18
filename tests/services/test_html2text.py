import pytest

from app.services.html2text import html2text


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ("<p>foo</p>", "foo"),
        (
            "<p>Hello, <img src='foo'></img><a href='https://www.google.com/earth/'>world</a>!",
            "Hello, world!",
        ),
    ],
)
def test_html2text(test_input: str, expected: str):
    assert html2text(test_input) == expected
