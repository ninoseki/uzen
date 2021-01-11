import json

import pytest

from app.models.scripts import Script
from app.models.snapshots import Snapshot
from app.schemas.utils import SnapshotResult


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan(client):
    # it matches with all snapshots
    payload = {"source": 'rule foo: bar {strings: $a = "foo" condition: $a}'}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == await Snapshot.all().count()


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
@pytest.mark.parametrize("size", [1, 5, 10])
async def test_yara_scan_with_size(client, size):
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
    }
    params = {"size": size}
    response = await client.post(
        "/api/yara/scan", data=json.dumps(payload), params=params
    )
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == size


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_yara_scan_with_target(client):
    # it should return all snapshots because every snapshot has "whois" which contains "foo"
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "target": "whois",
    }
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == await Snapshot.all().count()

    # it should return an empty list because there is no snapshot which has "certificate"
    payload = {
        "source": 'rule foo: bar {strings: $a = "foo" condition: $a}',
        "target": "certificate",
    }
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 200

    snapshots = response.json()
    assert len(snapshots) == 0


@pytest.mark.asyncio
async def test_yara_scan_with_invalid_input(client):
    payload = {"source": "boo"}
    response = await client.post("/api/yara/scan", data=json.dumps(payload))
    assert response.status_code == 422


async def mock_take_snapshot(*args, **kwargs):
    return SnapshotResult(
        snapshot=Snapshot(
            url="https://www.w3.org/",
            submitted_url="https://www.w3.org",
            status=200,
            hostname="example.com",
            ip_address="1.1.1.1",
            asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
            server="ECS (sjc/4E5D)",
            content_type="text/html; charset=UTF-8",
            content_length=1256,
            headers={},
            body='<html><body><script type="text/javascript" src="/2008/site/js/main"></body></html>',
            sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
            whois="foo",
            request={},
        ),
        screenshot=b"",
        scripts=[
            Script(
                url="https://www.w3.org/2008/site/js/main",
                content="foo",
                sha256="dummy",
            )
        ],
    )


async def mock_take_snapshot_without_script(*args, **kwargs):
    return SnapshotResult(
        snapshot=Snapshot(
            url="https://www.w3.org/",
            submitted_url="https://www.w3.org",
            status=200,
            hostname="example.com",
            ip_address="1.1.1.1",
            asn="AS15133 MCI Communications Services, Inc. d/b/a Verizon Business",
            server="ECS (sjc/4E5D)",
            content_type="text/html; charset=UTF-8",
            content_length=1256,
            headers={},
            body="<html><body></body></html>",
            sha256="fbc1a9f858ea9e177916964bd88c3d37b91a1e84412765e29950777f265c4b75",
            whois="foo",
            request={},
        ),
        screenshot=b"",
        scripts=[],
    )
