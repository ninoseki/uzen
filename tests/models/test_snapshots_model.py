import json

from uzen.models import Snapshot


def test_to_str():
    snapshot = Snapshot(
        url="http://example.com",
        status=200,
        hostname="example.com",
        ip_address="1.1.1.1",
        server="ECS (sjc/4E5D)",
        content_type="text/html; charset=UTF-8",
        content_length=1256,
        headers={},
        body="foo bar",
        screenshot="yoyo",
    )

    assert str(snapshot) == json.dumps(
        dict(
            id=None,
            url="http://example.com",
            status=200,
            hostname="example.com",
            ip_address="1.1.1.1",
            server="ECS (sjc/4E5D)",
            content_type="text/html; charset=UTF-8",
            content_length=1256,
            headers={},
            body="foo bar",
            screenshot="yoyo",
            created_at=None,
        )
    )
