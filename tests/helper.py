import datetime
import uuid
from uuid import UUID

from app.dataclasses.utils import ScriptFile, SnapshotResult
from app.models.rules import Rule
from app.models.scripts import File, Script
from app.models.snapshots import Snapshot


def make_snapshot(hostname: str = "example.com") -> Snapshot:
    return Snapshot(
        id=uuid.uuid4(),
        url=f"http://{hostname}/",
        submitted_url=f"http://{hostname}",
        status=200,
        hostname=hostname,
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


def make_script_file(hostname: str = "example.com") -> ScriptFile:
    return ScriptFile(
        script=Script(url="http://{hostname}/test.js", file_id="foo"),
        file=File(id="foo", content="foo"),
    )


async def make_snapshot_result() -> SnapshotResult:
    snapshot = make_snapshot()
    return SnapshotResult(snapshot=snapshot, screenshot=None, script_files=[],)


async def first_rule_id() -> UUID:
    rule = await Rule.all().first()
    return rule.id


async def first_snapshot_id() -> UUID:
    snapshot = await Snapshot.all().first()
    return snapshot.id
