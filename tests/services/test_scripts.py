import vcr

from tests.utils import make_snapshot
from uzen.services.scripts import ScriptBuilder


@vcr.use_cassette("tests/fixtures/vcr_cassettes/build_from_snapshot.yaml")
def test_build_from_snapshot():
    snapshot = make_snapshot()
    snapshot.body = '<html><body><script type="text/javascript" src="https://www.w3.org/2008/site/js/main"></body></html>'

    scripts = ScriptBuilder.build_from_snapshot(snapshot)
    assert len(scripts) == 1

    script = scripts[0]
    assert script.url == "https://www.w3.org/2008/site/js/main"
    assert (
        "/*! See W3C-specific code uncompressed at http://www.w3.org/2008/site/js/core.js */"
        in script.content
    )


@vcr.use_cassette(
    "tests/fixtures/vcr_cassettes/build_from_snapshot_with_relative_src.yaml"
)
def test_build_from_snapshot_with_relative_src():
    snapshot = make_snapshot()
    snapshot.url = "https://www.w3.org"
    snapshot.body = '<html><body><script type="text/javascript" src="/2008/site/js/main"></body></html>'

    scripts = ScriptBuilder.build_from_snapshot(snapshot)
    assert len(scripts) == 1

    script = scripts[0]
    assert script.url == "https://www.w3.org/2008/site/js/main"
    assert (
        "/*! See W3C-specific code uncompressed at http://www.w3.org/2008/site/js/core.js */"
        in script.content
    )


def test_build_from_snapshot_with_no_src():
    snapshot = make_snapshot()
    snapshot.body = '<html><body><script type="text/javascript"></body></html>'

    scripts = ScriptBuilder.build_from_snapshot(snapshot)
    assert len(scripts) == 0
