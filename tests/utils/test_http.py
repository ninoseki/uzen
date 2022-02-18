import pathlib

from app.utils.http import get_script_urls


def test_get_script_sources():
    path = pathlib.Path(__file__).parent / "../fixtures/test.html"
    with open(path) as f:
        fixture = f.read()

    sources = get_script_urls(
        url="http://example.com/test.php",
        html=fixture,
    )
    assert len(sources) == 2
    assert "http://example.com/vendor/jquery-3.2.1.min.js" in sources
    assert "http://example.com/js/main.js" in sources
