import pathlib

import pytest
import respx
from httpx import Response

from tests.utils import make_snapshot
from uzen.factories.scripts import ScriptFactory, get_script_sources


@pytest.mark.asyncio
@respx.mock
async def test_build_from_snapshot():
    snapshot = make_snapshot()
    snapshot.body = '<html><body><script type="text/javascript" src="https://www.w3.org/2008/site/js/main"></body></html>'
    respx.get("https://www.w3.org/2008/site/js/main").mock(
        Response(status_code=200, content="foo")
    )

    scripts = await ScriptFactory.from_snapshot(snapshot)
    assert len(scripts) == 1

    script = scripts[0]
    assert script.url == "https://www.w3.org/2008/site/js/main"
    assert "foo" in script.content


@respx.mock
@pytest.mark.asyncio
async def test_build_from_snapshot_with_relative_src():
    snapshot = make_snapshot()
    snapshot.url = "https://www.w3.org"
    snapshot.body = '<html><body><script type="text/javascript" src="/2008/site/js/main"></body></html>'
    respx.get("https://www.w3.org/2008/site/js/main").mock(
        Response(status_code=200, content="foo")
    )

    scripts = await ScriptFactory.from_snapshot(snapshot)
    assert len(scripts) == 1

    script = scripts[0]
    assert script.url == "https://www.w3.org/2008/site/js/main"
    assert "foo" in script.content


@pytest.mark.asyncio
async def test_build_from_snapshot_with_no_src():
    snapshot = make_snapshot()
    snapshot.body = '<html><body><script type="text/javascript"></body></html>'

    scripts = await ScriptFactory.from_snapshot(snapshot)
    assert len(scripts) == 0


def test_get_script_sources():
    path = pathlib.Path(__file__).parent / "../fixtures/test.html"
    with open(path) as f:
        fixture = f.read()

    sources = get_script_sources(url="http://example.com/test.php", body=fixture)
    assert len(sources) == 2
    assert "http://example.com/vendor/jquery-3.2.1.min.js" in sources
    assert "http://example.com/js/main.js" in sources
