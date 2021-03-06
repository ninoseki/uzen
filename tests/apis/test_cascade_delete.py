import httpx
import pytest

from app.models.match import Match
from app.models.rule import Rule
from app.models.script import Script
from app.models.snapshot import Snapshot
from tests.helper import first_rule_id, first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_delete_snapshot_with_scripts(client: httpx.AsyncClient):
    id_ = await first_snapshot_id()
    snapshot_count = await Snapshot.all().count()
    script_count = await Script.all().count()

    response = await client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert await Snapshot.all().count() == snapshot_count - 1
    assert await Script.all().count() == script_count - 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_delete_snapshot_with_matches(client: httpx.AsyncClient):
    id_ = await first_snapshot_id()
    snapshot_count = await Snapshot.all().count()
    match_count = await Match.all().count()

    response = await client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert await Snapshot.all().count() == snapshot_count - 1
    assert await Match.all().count() == match_count - 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_delete_rule_with_matches(client: httpx.AsyncClient):
    id_ = await first_rule_id()
    rule_count = await Rule.all().count()
    match_count = await Match.all().count()

    response = await client.delete(f"/api/rules/{id_}")
    assert response.status_code == 204

    assert await Rule.all().count() == rule_count - 1
    assert await Match.all().count() == match_count - 1
