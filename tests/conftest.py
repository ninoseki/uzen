import datetime
from typing import List

import httpx
import pytest
from starlette.config import environ
from tortoise import Tortoise
from tortoise.backends.base.config_generator import generate_config
from tortoise.exceptions import DBConnectionError

from uzen import create_app
from uzen.core import settings
from uzen.models.classifications import Classification
from uzen.models.dns_records import DnsRecord
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot


@pytest.fixture
def client():
    app = create_app()
    return httpx.AsyncClient(app=app, base_url="http://testserver")


def getDBConfig(app_label: str, db_url: str, modules: List[str]) -> dict:
    return generate_config(
        db_url,
        app_modules={app_label: modules},
        testing=True,
        connection_label=app_label,
    )


@pytest.fixture(autouse=True)
async def tortoise_db():
    db_url = environ.get("TORTOISE_TEST_DB", "sqlite://:memory:")
    config = getDBConfig(app_label="models", db_url=db_url, modules=settings.APP_MODELS)
    try:
        await Tortoise.init(config)
        await Tortoise._drop_databases()
    except DBConnectionError:
        pass

    await Tortoise.init(config)
    await Tortoise.generate_schemas()

    yield

    await Tortoise.close_connections()


@pytest.fixture
async def snapshots_setup(client):
    for i in range(0, 10):
        snapshot = Snapshot(
            id=i,
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
            body="foo bar",
            sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
            screenshot="yoyo",
            whois="foo",
            request={},
            created_at=datetime.datetime.now(),
        )
        await snapshot.save()


@pytest.fixture
async def scripts_setup(client, snapshots_setup):
    for i in range(0, 10):
        script = Script(
            id=i,
            snapshot_id=i,
            url=f"http://example{i}.com/test.js",
            content="foo bar",
            sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
            created_at=datetime.datetime.now(),
        )
        await script.save()


@pytest.fixture
async def dns_records_setup(client, snapshots_setup):
    for i in range(0, 5):
        record = DnsRecord(
            id=i,
            snapshot_id=i,
            value=f"1.1.1.{i}",
            type="A",
            created_at=datetime.datetime.now(),
        )
        await record.save()


@pytest.fixture
async def classifications_setup(client, snapshots_setup):
    for i in range(0, 5):
        classification = Classification(
            id=i,
            snapshot_id=i,
            name="test",
            malicious=True,
            created_at=datetime.datetime.now(),
        )
        await classification.save()


@pytest.fixture
def patch_datetime_now(monkeypatch):
    FAKE_TIME = datetime.datetime(2020, 12, 25, 17, 5, 55)

    class mydatetime:
        @classmethod
        def now(cls):
            return FAKE_TIME

    monkeypatch.setattr(datetime, "datetime", mydatetime)
