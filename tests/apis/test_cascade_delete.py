import pytest

from uzen.models.matches import Match
from uzen.models.rules import Rule
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot


@pytest.mark.asyncio
@pytest.mark.usefixtures("scripts_setup")
async def test_delete_snapshot_with_scripts(client):
    snapshot_count = await Snapshot.all().count()
    script_count = await Script.all().count()

    response = await client.delete("/api/snapshots/1")
    assert response.status_code == 204

    assert await Snapshot.all().count() == snapshot_count - 1
    assert await Script.all().count() == script_count - 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_delete_snapshot_with_matches(client):
    snapshot_count = await Snapshot.all().count()
    match_count = await Match.all().count()

    response = await client.delete("/api/snapshots/1")
    assert response.status_code == 204

    assert await Snapshot.all().count() == snapshot_count - 1
    assert await Match.all().count() == match_count - 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("matches_setup")
async def test_delete_rule_with_matches(client):
    rule_count = await Rule.all().count()
    match_count = await Match.all().count()

    response = await client.delete("/api/rules/1")
    assert response.status_code == 204

    assert await Rule.all().count() == rule_count - 1
    assert await Match.all().count() == match_count - 1
