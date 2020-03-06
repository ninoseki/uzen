from starlette.config import environ
from starlette.testclient import TestClient
from tortoise import Tortoise
from tortoise import Tortoise, run_async
from tortoise.backends.base.config_generator import generate_config
from tortoise.contrib.test import finalizer, initializer
from tortoise.exceptions import DBConnectionError
from typing import List
import asyncio
import datetime
import httpx
import pytest

# This line would raise an error if we use it after 'settings' has been imported.
environ["TESTING"] = "TRUE"

from uzen import settings  # noqa
from uzen import create_app  # noqa
from uzen.models import Snapshot  # noqa


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
    config = getDBConfig(
        app_label="models",
        db_url=db_url,
        modules=settings.APP_MODELS
    )
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
            url=f"http://example{i}.com",
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
            created_at=datetime.datetime.now()

        )
        await snapshot.save()


@pytest.fixture
def patch_datetime_now(monkeypatch):
    FAKE_TIME = datetime.datetime(2020, 12, 25, 17, 5, 55)

    class mydatetime:
        @classmethod
        def now(cls):
            return FAKE_TIME

    monkeypatch.setattr(datetime, "datetime", mydatetime)


def make_snapshot() -> Snapshot:
    return Snapshot(
        id=1,
        url=f"http://example.com",
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
        created_at=datetime.datetime.now().isoformat()
    )
