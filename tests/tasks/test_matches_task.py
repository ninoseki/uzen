import pytest

from uzen.models.matches import Match
from uzen.models.rules import Rule
from uzen.models.snapshots import Snapshot
from uzen.tasks.matches import MatchinbgTask


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_matching_taskl(client):
    rule = Rule(
        name="test",
        target="body",
        source='rule foo: bar {strings: $a = "foo" condition: $a}',
    )
    await rule.save()

    snapshot = await Snapshot.get(id=1)

    matches = await Match.all()
    assert len(matches) == 0

    await MatchinbgTask.process(snapshot)

    matches = await Match.all()
    assert len(matches) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("snapshots_setup")
async def test_matching_task_with_zero_matches(client):
    rule = Rule(
        name="test",
        target="whois",
        source='rule foo: bar {strings: $a = "bar" condition: $a}',
    )
    await rule.save()

    snapshot = await Snapshot.get(id=1)

    matches = await Match.all()
    assert len(matches) == 0

    await MatchinbgTask.process(snapshot)

    matches = await Match.all()
    assert len(matches) == 0
