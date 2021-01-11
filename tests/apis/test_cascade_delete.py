import pytest

from app.models.matches import Match
from app.models.rules import Rule
from app.models.scripts import Script
from app.models.snapshots import Snapshot
from tests.utils import first_rule_id, first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_delete_snapshot_with_scripts(client):
    id_ = await first_snapshot_id()
    snapshot_count = await Snapshot.all().count()
    script_count = await Script.all().count()

    response = await client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert await Snapshot.all().count() == snapshot_count - 1
    assert await Script.all().count() == script_count - 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_delete_snapshot_with_matches(client):
    id_ = await first_snapshot_id()
    snapshot_count = await Snapshot.all().count()
    match_count = await Match.all().count()

    response = await client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert await Snapshot.all().count() == snapshot_count - 1
    assert await Match.all().count() == match_count - 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_delete_rule_with_matches(client):
    id_ = await first_rule_id()
    rule_count = await Rule.all().count()
    match_count = await Match.all().count()

    response = await client.delete(f"/api/rules/{id_}")
    assert response.status_code == 204

    assert await Rule.all().count() == rule_count - 1
    assert await Match.all().count() == match_count - 1
