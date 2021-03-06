from typing import Optional

import pytest

from app.schemas.snapshot import (
    CreateSnapshotPayload,
    SnapshotBasicAttributes,
    remove_sharp_and_question_from_tail,
)


@pytest.mark.parametrize(
    "url,device_name,error",
    [
        ("http://example.com", None, None),
        ("http://nope.example.com", None, ValueError),
        ("http://example.com", "iPhone 11", None),
        ("http://example.com", "foo", ValueError),
    ],
)
def test_create_snapsnot_payload(url: str, device_name: Optional[str], error):
    if error is not None:
        with pytest.raises(error):
            CreateSnapshotPayload(url=url, device_name=device_name)
    else:
        payload = CreateSnapshotPayload(url=url, device_name=device_name)
        assert payload.url == "http://example.com"
        assert payload.device_name == device_name


def test_create_snapsnot_payload_with_headers():
    # header keys should be lower cases
    payload = CreateSnapshotPayload(url="http://example.com", headers={"Foo": "bar"})
    assert payload.headers == {"foo": "bar"}


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://example.com#", "http://example.com"),
        ("http://example.com?", "http://example.com"),
    ],
)
def test_basic_attributes(url: str, expected: str):
    basic = SnapshotBasicAttributes(
        url=url,
        submitted_url=url,
        hostname="example.com",
        ip_address="1.1.1.1",
        asn="",
        country_code="",
        status=200,
        body="",
        sha256="",
    )
    assert basic.url == expected
    assert basic.submitted_url == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        ("foo#", "foo"),
        ("foo?", "foo"),
        ("foo", "foo"),
    ],
)
def test_remove_sharp_and_question_from_tail(input: str, expected: str):
    assert remove_sharp_and_question_from_tail(input) == expected
