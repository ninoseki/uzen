import pytest
import respx

from tests.utils import make_snapshot
from uzen.services.scripts import ScriptBuilder


@pytest.mark.asyncio
@respx.mock
async def test_build_from_snapshot():
    snapshot = make_snapshot()
    snapshot.body = '<html><body><script type="text/javascript" src="https://www.w3.org/2008/site/js/main"></body></html>'
    respx.get("https://www.w3.org/2008/site/js/main", content="foo")

    scripts = await ScriptBuilder.build_from_snapshot(snapshot)
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
    respx.get("https://www.w3.org/2008/site/js/main", content="foo")

    scripts = await ScriptBuilder.build_from_snapshot(snapshot)
    assert len(scripts) == 1

    script = scripts[0]
    assert script.url == "https://www.w3.org/2008/site/js/main"
    assert "foo" in script.content


@pytest.mark.asyncio
async def test_build_from_snapshot_with_no_src():
    snapshot = make_snapshot()
    snapshot.body = '<html><body><script type="text/javascript"></body></html>'

    scripts = await ScriptBuilder.build_from_snapshot(snapshot)
    assert len(scripts) == 0
