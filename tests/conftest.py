import asyncio
import datetime
from asyncio.events import AbstractEventLoop
from typing import List
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import nest_asyncio
import pytest
from _pytest.monkeypatch import MonkeyPatch
from starlette.config import environ
from tortoise import Tortoise
from tortoise.backends.base.config_generator import generate_config
from tortoise.exceptions import DBConnectionError

from app import create_app, dataclasses, models
from app.api.dependencies.arq import get_arq_redis
from app.api.dependencies.verification import verify_api_key
from app.core import settings
from app.factories.html import HTMLFactory
from app.services.certificate import Certificate
from app.services.ip2asn import IP2ASN
from app.services.whois import Whois
from app.utils.hash import sha256
from tests.fake_arq import FakeArqRedis
from tests.testclient import TestClient

nest_asyncio.apply()


def get_db_config(app_label: str, db_url: str, modules: List[str]) -> dict:
    return generate_config(
        db_url,
        app_modules={app_label: modules},
        testing=True,
        connection_label=app_label,
    )


async def init_db():
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


@pytest.fixture(autouse=True)
async def tortoise_db():
    await init_db()

    yield

    await Tortoise.close_connections()


async def override_get_arq_redis():
    yield FakeArqRedis()


async def override_verify_api_key():
    yield None


@pytest.fixture
async def client(monkeypatch: MonkeyPatch):
    monkeypatch.setattr("app.database.init_db", init_db)

    app = create_app()

    # use fake arq redis for testing
    app.dependency_overrides[get_arq_redis] = override_get_arq_redis
    # do not check API key
    app.dependency_overrides[verify_api_key] = override_verify_api_key

    with TestClient(
        app=app,
        base_url="http://testserver",
    ) as client_:
        client_.headers = {"secret-api-key": str(settings.SECRET_API_KEY)}
        yield client_


@pytest.fixture
async def client_without_verity_api_key_override(monkeypatch: MonkeyPatch):
    monkeypatch.setattr("app.database.init_db", init_db)

    app = create_app()

    # use fake arq redis for testing
    app.dependency_overrides[get_arq_redis] = override_get_arq_redis

    with TestClient(
        app=app,
        base_url="http://testserver",
    ) as client_:
        client_.headers = {"secret-api-key": str(settings.SECRET_API_KEY)}
        yield client_


@pytest.fixture
def event_loop(client: TestClient) -> AbstractEventLoop:
    yield client.task.get_loop()


@pytest.fixture
def api_key(event_loop: asyncio.AbstractEventLoop) -> models.APIKey:
    api_key = models.APIKey(id="2e08d082-1ebc-4a7b-824f-3c08c6a305db")
    event_loop.run_until_complete(api_key.save())
    return api_key


@pytest.fixture
def html(event_loop: asyncio.AbstractEventLoop) -> models.HTML:
    html_str = "<p>foo</p>"
    html = HTMLFactory.from_str(html_str)
    event_loop.run_until_complete(html.save())
    return html


@pytest.fixture
def whois(event_loop: asyncio.AbstractEventLoop) -> models.Whois:
    whois_str = "foo"
    whois = models.Whois(id=sha256(whois_str), content=whois_str)
    event_loop.run_until_complete(whois.save())
    return whois


@pytest.fixture
def snapshots(
    event_loop: asyncio.AbstractEventLoop,
    api_key: models.APIKey,
    html: models.HTML,
    whois: models.Whois,
) -> List[models.Snapshot]:
    snapshots: List[models.Snapshot] = []
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
        snapshot.api_key_id = api_key.id
        event_loop.run_until_complete(snapshot.save())

        har = models.HAR(data={"foo": "bar"})
        har.snapshot_id = snapshot.id
        event_loop.run_until_complete(har.save())

        snapshots.append(snapshot)

    return snapshots


@pytest.fixture
def scripts(
    snapshots: List[models.Snapshot],
    event_loop: asyncio.AbstractEventLoop,
) -> List[models.Script]:
    scripts: List[models.Script] = []
    snapshot_ids = [str(snapshot.id) for snapshot in snapshots]
    for id_ in snapshot_ids:
        file_id = uuid4().hex
        file = models.File(id=file_id, content="foo")
        event_loop.run_until_complete(file.save())

        script = models.Script(
            snapshot_id=id_,
            file_id=file_id,
            url=f"http://example{id_}.com/test.js",
            created_at=datetime.datetime.now(),
        )
        event_loop.run_until_complete(script.save())
        scripts.append(script)

    return scripts


@pytest.fixture
def dns_records(
    snapshots: List[models.Snapshot],
    event_loop: asyncio.AbstractEventLoop,
) -> List[models.DNSRecord]:
    snapshot_ids = [str(snapshot.id) for snapshot in snapshots]
    records: List[models.DNSRecord] = []
    for id_ in snapshot_ids:
        record = models.DNSRecord(
            snapshot_id=id_,
            value="1.1.1.1",
            type="A",
            created_at=datetime.datetime.now(),
        )
        event_loop.run_until_complete(record.save())
        records.append(record)

    return records


@pytest.fixture
def classifications(
    snapshots: List[models.Snapshot],
    event_loop: asyncio.AbstractEventLoop,
) -> List[models.Classification]:
    snapshot_ids = [str(snapshot.id) for snapshot in snapshots]
    classifications: List[models.Classification] = []
    for id_ in snapshot_ids:
        classification = models.Classification(
            snapshot_id=id_,
            name="test",
            malicious=True,
            created_at=datetime.datetime.now(),
        )
        event_loop.run_until_complete(classification.save())
        classifications.append(classification)

    return classifications


@pytest.fixture
def rules(event_loop: asyncio.AbstractEventLoop) -> List[models.Rule]:
    rules: List[models.Rule] = []
    for i in range(1, 6):
        rule = models.Rule(
            name=f"test{i}",
            target="html",
            source='rule foo: bar {strings: $a = "lmn" condition: $a}',
            created_at=datetime.datetime.now(),
        )
        event_loop.run_until_complete(rule.save())
        rules.append(rule)

    return rules


@pytest.fixture
def matches(
    snapshots: List[models.Snapshot],
    rules: List[models.Rule],
    event_loop: asyncio.AbstractEventLoop,
) -> List[models.Match]:
    snapshot_ids = [snapshot.id for snapshot in snapshots]
    rule_ids = [rule.id for rule in rules]
    zipped = zip(snapshot_ids, rule_ids)

    matches: List[models.Match] = []
    for (snapshot_id, rule_id) in list(zipped):
        match = models.Match(
            snapshot_id=snapshot_id,
            rule_id=rule_id,
            matches="[]",
            created_at=datetime.datetime.now(),
        )
        event_loop.run_until_complete(match.save())
        matches.append(match)

    return matches


@pytest.fixture
def patch_whois_lookup(monkeypatch: MonkeyPatch):
    monkeypatch.setattr(
        Whois, "lookup", AsyncMock(return_value=dataclasses.Whois(content="foo"))
    )


@pytest.fixture
def patch_ip2asn_lookup(monkeypatch: MonkeyPatch):
    monkeypatch.setattr(
        IP2ASN,
        "lookup",
        AsyncMock(
            return_value=dataclasses.IP2ASNResponse(
                ip_address="1.1.1.1",
                country_code="AU",
                description="dummy",
                asn="AS15133",
            )
        ),
    )


@pytest.fixture
def patch_certificate_load_from_url(monkeypatch: MonkeyPatch):
    monkeypatch.setattr(Certificate, "load_from_url", Mock(return_value=None))
