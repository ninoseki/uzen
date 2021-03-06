import datetime
from typing import List
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import httpx
import pytest
from _pytest.monkeypatch import MonkeyPatch
from starlette.config import environ
from tortoise import Tortoise
from tortoise.backends.base.config_generator import generate_config
from tortoise.exceptions import DBConnectionError

from app import create_app, dataclasses, models
from app.core import settings
from app.services.certificate import Certificate
from app.services.ip2asn import IP2ASN
from app.services.whois import Whois
from app.utils.hash import calculate_sha256


@pytest.fixture
async def client():
    app = create_app()
    async with httpx.AsyncClient(
        app=app,
        base_url="http://testserver",
        headers={"api-key": settings.GLOBAL_API_KEY},
    ) as client:
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
        app_label="models",
        db_url=db_url,
        modules=settings.APP_MODELS,
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
    html = models.HTML(id=calculate_sha256("foo bar"), content="foo bar")
    await html.save()

    whois = models.Whois(id=calculate_sha256("foo"), content="foo")
    await whois.save()

    for i in range(1, 11):
        snapshot = models.Snapshot(
            url=f"http://example{i}.com/",
            submitted_url=f"http://example{i}.com",
            status=200,
            hostname="example.com",
            ip_address="1.1.1.1",
            asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
            country_code="AU",
            request_headers={},
            response_headers={},
            created_at=datetime.datetime.now(),
        )
        snapshot.html_id = html.id
        snapshot.whois_id = whois.id
        await snapshot.save()

        har = models.HAR(data={"foo": "bar"})
        har.snapshot_id = snapshot.id
        await har.save()


@pytest.fixture
async def scripts_setup(client, snapshots_setup):
    snapshot_ids = await models.Snapshot().all().values_list("id", flat=True)
    for id_ in snapshot_ids:
        file_id = uuid4().hex
        file = models.File(id=file_id, content="foo")
        await file.save()

        script = models.Script(
            snapshot_id=id_,
            file_id=file_id,
            url=f"http://example{id_}.com/test.js",
            created_at=datetime.datetime.now(),
        )
        await script.save()


@pytest.fixture
async def dns_records_setup(client, snapshots_setup):
    snapshot_ids = await models.Snapshot().all().values_list("id", flat=True)
    for id_ in snapshot_ids:
        record = models.DnsRecord(
            snapshot_id=id_,
            value="1.1.1.1",
            type="A",
            created_at=datetime.datetime.now(),
        )
        await record.save()


@pytest.fixture
async def classifications_setup(client, snapshots_setup):
    snapshot_ids = await models.Snapshot().all().values_list("id", flat=True)
    for id_ in snapshot_ids:
        classification = models.Classification(
            snapshot_id=id_,
            name="test",
            malicious=True,
            created_at=datetime.datetime.now(),
        )
        await classification.save()


@pytest.fixture
async def rules_setup(client):
    for i in range(1, 6):
        rule = models.Rule(
            name=f"test{i}",
            target="html",
            source='rule foo: bar {strings: $a = "lmn" condition: $a}',
            created_at=datetime.datetime.now(),
        )
        await rule.save()


@pytest.fixture
async def matches_setup(client, snapshots_setup, rules_setup):
    snapshot_ids = await models.Snapshot().all().values_list("id", flat=True)
    rules_ids = await models.Rule().all().values_list("id", flat=True)
    zipped = zip(snapshot_ids, rules_ids)

    for (snapshot_id, rule_id) in list(zipped):
        match = models.Match(
            snapshot_id=snapshot_id,
            rule_id=rule_id,
            matches="[]",
            created_at=datetime.datetime.now(),
        )
        await match.save()


@pytest.fixture
async def first_rule_id(client, rules_setup) -> UUID:
    rule = await models.Rule.all().first()
    return rule.id


@pytest.fixture
async def first_snapshot_id(client, snapshots_setup) -> UUID:
    snapshot = await models.Snapshot.all().first()
    return snapshot.id


@pytest.fixture
def patch_whois_lookup(monkeypatch: MonkeyPatch):
    monkeypatch.setattr(
        Whois, "lookup", AsyncMock(return_value=dataclasses.Whois(content="foo"))
    )


@pytest.fixture
def patch_ip2asn_lookup(monkeypatch: MonkeyPatch):
    monkeypatch.setattr(IP2ASN, "lookup", AsyncMock(return_value={"asn": "AS15133"}))


@pytest.fixture
def patch_certificate_load_from_url(monkeypatch: MonkeyPatch):
    monkeypatch.setattr(Certificate, "load_from_url", Mock(return_value=None))
