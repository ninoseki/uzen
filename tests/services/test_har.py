import json
import pathlib

from app.services.har import HarReader

path = pathlib.Path(__file__).parent / "../fixtures/w3c.har"
with open(path) as f:
    fixture = json.loads(f.read())


def test_find_script_files():
    reader = HarReader(fixture)
    script_files = reader.find_script_files()

    assert len(script_files) == 2

    assert script_files[0].script.url == "https://www.w3.org/2008/site/js/main"
    assert (
        script_files[0].file.id
        == "b91c5c44ca24917d233d5316c4b929341a24c8eaae1fb4ab90652d63e73811e2"
    )

    assert script_files[1].script.url == "https://www.w3.org/analytics/piwik/matomo.js"
    assert (
        script_files[1].file.id
        == "0995371a359a4a701d66f8b183de6144de9a042e5bac84b6f920968f51567742"
    )


def test_find_request():
    reader = HarReader(fixture)
    request = reader.find_request()

    assert request.get("url") == "https://www.w3.org/"
