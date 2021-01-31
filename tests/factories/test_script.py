import pytest
import respx
from httpx import Response

from app.factories.script import ScriptFactory
from tests.helper import make_html, make_snapshot


@pytest.mark.asyncio
@respx.mock
async def test_build_from_snapshot():
    snapshot = make_snapshot()
    html = make_html()

    html.content = '<html><body><script type="text/javascript" src="https://www.w3.org/2008/site/js/main"></body></html>'

    snapshot.html = html

    respx.get("https://www.w3.org/2008/site/js/main").mock(
        Response(status_code=200, content="foo")
    )

    script_files = await ScriptFactory.from_snapshot(snapshot)
    assert len(script_files) == 1

    script = script_files[0].script
    assert script.url == "https://www.w3.org/2008/site/js/main"

    file = script_files[0].file
    assert "foo" in file.content


@respx.mock
@pytest.mark.asyncio
async def test_build_from_snapshot_with_relative_src():
    snapshot = make_snapshot()
    html = make_html()

    snapshot.url = "https://www.w3.org"
    html.content = '<html><body><script type="text/javascript" src="/2008/site/js/main"></body></html>'

    snapshot.html = html

    respx.get("https://www.w3.org/2008/site/js/main").mock(
        Response(status_code=200, content="foo")
    )

    script_files = await ScriptFactory.from_snapshot(snapshot)
    assert len(script_files) == 1

    script = script_files[0].script
    assert script.url == "https://www.w3.org/2008/site/js/main"

    file = script_files[0].file
    assert "foo" in file.content


@pytest.mark.asyncio
async def test_build_from_snapshot_with_no_src():
    snapshot = make_snapshot()
    html = make_html()

    html.content = '<html><body><script type="text/javascript"></body></html>'

    snapshot.html = html

    script_files = await ScriptFactory.from_snapshot(snapshot)
    assert len(script_files) == 0
