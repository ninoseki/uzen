import pytest
import respx
from httpx import Response

from app.factories.stylesheet import StylesheetFactory
from tests.helper import make_html, make_snapshot


@pytest.mark.asyncio
@respx.mock
async def test_build_from_snapshot():
    snapshot = make_snapshot()
    html = make_html()

    html.content = '<html><body><link href="/2008/site/css/minimum" rel="stylesheet" type="text/css" /></body></html>'
    snapshot.html = html

    url = f"{snapshot.url}2008/site/css/minimum"

    respx.get(url).mock(
        Response(status_code=200, content="foo", headers={"content-type": "text/css"})
    )

    stylesheet_files = await StylesheetFactory.from_snapshot(snapshot)
    assert len(stylesheet_files) == 1

    stylesheet = stylesheet_files[0].stylesheet
    assert stylesheet.url == url

    file = stylesheet_files[0].file
    assert "foo" in file.content
