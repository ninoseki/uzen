import pytest

from uzen.schemas.snapshots import CreateSnapshotPayload


def test_create_snapsnot_payload():
    payload = CreateSnapshotPayload(url="http://example.com")
    assert payload.url == "http://example.com"

    with pytest.raises(ValueError):
        CreateSnapshotPayload(url="http://nope.example.com")
