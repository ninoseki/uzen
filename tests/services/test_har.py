import json
import pathlib

import dateutil.parser

from app import dataclasses
from app.services.har import HARReader


def datetime_decoder(data: dict) -> dict:
    for field, value in data.items():
        if field in ["startedDateTime", "expires"]:
            data[field] = dateutil.parser.parse(value)
    return data


path = pathlib.Path(__file__).parent / "../fixtures/w3c.har"
with open(path) as f:
    fixture = json.loads(f.read(), object_hook=datetime_decoder)


def test_find_script_files():
    har = dataclasses.HAR.from_dict(fixture)
    reader = HARReader(har)
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
    har = dataclasses.HAR.from_dict(fixture)
    reader = HARReader(har)
    request = reader.find_request()

    assert request.url == "https://www.w3.org/"
