import datetime
import uuid
from uuid import UUID

from app import models
from app.dataclasses.utils import ScriptFile, SnapshotResult
from app.utils.hash import calculate_sha256


def make_html() -> models.HTML:
    return models.HTML(id=calculate_sha256("foo bar"), content="foo bar")


def make_snapshot(hostname: str = "example.com") -> models.Snapshot:
    return models.Snapshot(
        id=uuid.uuid4(),
        url=f"http://{hostname}/",
        submitted_url=f"http://{hostname}",
        status=200,
        hostname=hostname,
        ip_address="1.1.1.1",
        asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
        response_headers={},
        request_headers={},
        created_at=datetime.datetime.now(),
    )


def make_script_file(hostname: str = "example.com") -> ScriptFile:
    return ScriptFile(
        script=models.Script(url="http://{hostname}/test.js", file_id="foo"),
        file=models.File(id="foo", content="foo"),
    )


async def make_snapshot_result() -> SnapshotResult:
    snapshot = make_snapshot()
    html = make_html()
    return SnapshotResult(
        snapshot=snapshot,
        screenshot=None,
        script_files=[],
        html=html,
        whois=None,
        certificate=None,
        har=None,
    )


async def first_rule_id() -> UUID:
    rule = await models.Rule.all().first()
    return rule.id


async def first_snapshot_id() -> UUID:
    snapshot = await models.Snapshot.all().first()
    return snapshot.id
