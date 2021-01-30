import pytest

from app.schemas.snapshot import (
    BasicAttributes,
    CreateSnapshotPayload,
    remove_sharp_and_question_from_tail,
)


def test_create_snapsnot_payload():
    payload = CreateSnapshotPayload(url="http://example.com")
    assert payload.url == "http://example.com"

    with pytest.raises(ValueError):
        CreateSnapshotPayload(url="http://nope.example.com")

    # with device name
    CreateSnapshotPayload(url="http://example.com", device_name="iPhone 11")

    with pytest.raises(ValueError):
        CreateSnapshotPayload(url="http://example.com", device_name="foo")


def test_create_snapsnot_payload_with_headers():
    # header keys should be lower cases
    payload = CreateSnapshotPayload(url="http://example.com", headers={"Foo": "bar"})
    assert payload.headers == {"foo": "bar"}


def test_basic_attributes():
    basic = BasicAttributes(
        url="http://example.com#",
        submitted_url="http://example.com#",
        hostname="example.com",
        ip_address="1.1.1.1",
        asn="",
        status=200,
        body="",
        sha256="",
    )
    assert basic.url == "http://example.com"
    assert basic.submitted_url == "http://example.com"

    basic = BasicAttributes(
        url="http://example.com?",
        submitted_url="http://example.com?",
        hostname="example.com",
        ip_address="1.1.1.1",
        asn="",
        status=200,
        body="",
        sha256="",
    )
    assert basic.url == "http://example.com"
    assert basic.submitted_url == "http://example.com"


def test_remove_sharp_and_question_from_tail():
    assert remove_sharp_and_question_from_tail("foo#") == "foo"
    assert remove_sharp_and_question_from_tail("foo?") == "foo"
    assert remove_sharp_and_question_from_tail("foo") == "foo"
