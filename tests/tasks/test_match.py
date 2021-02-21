import pytest

from app.models.match import Match
from app.models.rule import Rule
from app.models.snapshot import Snapshot
from app.tasks.match import MatchingTask
from tests.helper import first_snapshot_id


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_matching_taskl(client):
    rule = Rule(
        name="test",
        target="html",
        source='rule foo: bar {strings: $a = "foo" condition: $a}',
    )
    await rule.save()

    id_ = await first_snapshot_id()
    snapshot = await Snapshot.get(id=id_)

    assert await Match.all().count() == 0

    await MatchingTask.process(snapshot)

    assert await Match.all().count() == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_matching_task_with_zero_matches(client):
    rule = Rule(
        name="test",
        target="whois",
        source='rule foo: bar {strings: $a = "bar" condition: $a}',
    )
    await rule.save()

    id_ = await first_snapshot_id()
    snapshot = await Snapshot.get(id=id_)

    assert await Match.all().count() == 0

    await MatchingTask.process(snapshot)

    assert await Match.all().count() == 0
