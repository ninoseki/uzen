import datetime
from typing import List
from uuid import UUID, uuid4

import httpx
import pytest
from starlette.config import environ
from tortoise import Tortoise
from tortoise.backends.base.config_generator import generate_config
from tortoise.exceptions import DBConnectionError

from app import create_app
from app.core import settings
from app.models.classifications import Classification
from app.models.dns_records import DnsRecord
from app.models.file import File
from app.models.html import HTML
from app.models.matches import Match
from app.models.rules import Rule
from app.models.scripts import Script
from app.models.snapshots import Snapshot
from app.models.whois import Whois
from app.utils.hash import calculate_sha256


@pytest.fixture
async def client():
    app = create_app()
    async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
        yield client


def get_db_config(app_label: str, db_url: str, modules: List[str]) -> dict:
    return generate_config(
        db_url,
        app_modules={app_label: modules},
        testing=True,
        connection_label=app_label,
    )


@pytest.fixture(autouse=True)
async def tortoise_db():
    db_url = environ.get("TORTOISE_TEST_DB", "sqlite://:memory:")
    config = get_db_config(
        app_label="models", db_url=db_url, modules=settings.APP_MODELS,
    )
    try:
        await Tortoise.init(config)
        await Tortoise._drop_databases()
    except DBConnectionError:
        pass

    await Tortoise.init(config, _create_db=True)
    await Tortoise.generate_schemas()

    yield

    await Tortoise.close_connections()


@pytest.fixture
async def snapshots_setup(client):
    html = HTML(id=calculate_sha256("foo bar"), content="foo bar")
    await html.save()

    whois = Whois(id=calculate_sha256("foo"), content="foo")
    await whois.save()

    for i in range(1, 11):
        snapshot = Snapshot(
            url=f"http://example{i}.com/",
            submitted_url=f"http://example{i}.com",
            status=200,
            hostname="example.com",
            ip_address="1.1.1.1",
            asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
            server="ECS (sjc/4E5D)",
            content_type="text/html; charset=UTF-8",
            content_length=1256,
            headers={},
            request={},
            created_at=datetime.datetime.now(),
        )
        snapshot.html_id = html.id
        snapshot.whois_id = whois.id
        await snapshot.save()


@pytest.fixture
async def scripts_setup(client, snapshots_setup):
    snapshot_ids = await Snapshot().all().values_list("id", flat=True)
    for id_ in snapshot_ids:
        file_id = uuid4().hex
        file = File(id=file_id, content="foo")
        await file.save()

        script = Script(
            snapshot_id=id_,
            file_id=file_id,
            url=f"http://example{id_}.com/test.js",
            created_at=datetime.datetime.now(),
        )
        await script.save()


@pytest.fixture
async def dns_records_setup(client, snapshots_setup):
    snapshot_ids = await Snapshot().all().values_list("id", flat=True)
    for id_ in snapshot_ids:
        record = DnsRecord(
            snapshot_id=id_,
            value="1.1.1.1",
            type="A",
            created_at=datetime.datetime.now(),
        )
        await record.save()


@pytest.fixture
async def classifications_setup(client, snapshots_setup):
    snapshot_ids = await Snapshot().all().values_list("id", flat=True)
    for id_ in snapshot_ids:
        classification = Classification(
            snapshot_id=id_,
            name="test",
            malicious=True,
            created_at=datetime.datetime.now(),
        )
        await classification.save()


@pytest.fixture
async def rules_setup(client):
    for i in range(1, 6):
        rule = Rule(
            name=f"test{i}",
            target="html",
            source='rule foo: bar {strings: $a = "lmn" condition: $a}',
            created_at=datetime.datetime.now(),
        )
        await rule.save()


@pytest.fixture
async def matches_setup(client, snapshots_setup, rules_setup):
    snapshot_ids = await Snapshot().all().values_list("id", flat=True)
    rules_ids = await Rule().all().values_list("id", flat=True)
    zipped = zip(snapshot_ids, rules_ids)

    for (snapshot_id, rule_id) in list(zipped):
        match = Match(
            snapshot_id=snapshot_id,
            rule_id=rule_id,
            matches="[]",
            created_at=datetime.datetime.now(),
        )
        await match.save()


@pytest.fixture
async def first_rule_id(client, rules_setup) -> UUID:
    rule = await Rule.all().first()
    return rule.id


@pytest.fixture
async def first_snapshot_id(client, snapshots_setup) -> UUID:
    snapshot = await Snapshot.all().first()
    return snapshot.id


@pytest.fixture
def patch_datetime_now(monkeypatch):
    FAKE_TIME = datetime.datetime(2020, 12, 25, 17, 5, 55)

    class mydatetime:
        @classmethod
        def now(cls):
            return FAKE_TIME

    monkeypatch.setattr(datetime, "datetime", mydatetime)
