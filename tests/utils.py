import datetime
import uuid
from uuid import UUID

from uzen.models.rules import Rule
from uzen.models.snapshots import Snapshot
from uzen.schemas.utils import SnapshotResult


def make_snapshot() -> Snapshot:
    return Snapshot(
        id=uuid.uuid4(),
        url=f"http://example.com/",
        submitted_url="http://example.com",
        status=200,
        hostname="example.com",
        ip_address="1.1.1.1",
        asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
        server="ECS (sjc/4E5D)",
        content_type="text/html; charset=UTF-8",
        content_length=1256,
        headers={},
        body="foo bar",
        sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
        whois="foo",
        request={},
        created_at=datetime.datetime.now(),
    )


async def make_snapshot_result() -> SnapshotResult:
    return SnapshotResult(
        snapshot=Snapshot(
            id=uuid.uuid4(),
            url="http://example.com/",
            submitted_url="http://example.com",
            status=200,
            hostname="example.com",
            ip_address="1.1.1.1",
            asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
            server="ECS (sjc/4E5D)",
            content_type="text/html; charset=UTF-8",
            content_length=1256,
            headers={},
            body="foo bar",
            sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
            screenshot="yoyo",
            whois="foo",
            request={},
            created_at=datetime.datetime.now(),
        ),
        screenshot=b"",
        scripts=[],
    )


async def first_rule_id() -> UUID:
    rule = await Rule.all().first()
    return rule.id


async def first_snapshot_id() -> UUID:
    snapshot = await Snapshot.all().first()
    return snapshot.id
