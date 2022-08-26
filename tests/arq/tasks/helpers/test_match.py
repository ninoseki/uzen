from typing import List

import pytest

from app import models
from app.arq.tasks.helpers.match import MatchingHelper


@pytest.mark.asyncio
@pytest.mark.usefixtures("client")
async def test_matching_task(snapshots: List[models.Snapshot]):
    rule = models.Rule(
        name="test",
        target="html",
        source='rule foo: bar {strings: $a = "foo" condition: $a}',
    )
    await rule.save()

    id_ = snapshots[0].id
    snapshot = await models.Snapshot.get(id=id_)

    assert await models.Match.all().count() == 0

    await MatchingHelper.process(snapshot)

    assert await models.Match.all().count() == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("client")
async def test_matching_task_with_zero_matches(snapshots: List[models.Snapshot]):
    rule = models.Rule(
        name="test",
        target="whois",
        source='rule foo: bar {strings: $a = "bar" condition: $a}',
    )
    await rule.save()

    id_ = snapshots[0].id
    snapshot = await models.Snapshot.get(id=id_)

    assert await models.Match.all().count() == 0

    await MatchingHelper.process(snapshot)

    assert await models.Match.all().count() == 0
