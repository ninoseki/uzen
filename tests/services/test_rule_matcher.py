import datetime
import uuid

import pytest

from uzen.models.rules import Rule
from uzen.models.snapshots import Snapshot
from uzen.services.rule_matcher import RuleMatcher


@pytest.fixture
async def rule_setup(client):
    rule = Rule(
        id=uuid.uuid4(),
        name="test",
        target="script",
        source='rule foo: bar {strings: $a = "foo" condition: $a}',
        created_at=datetime.datetime.now(),
    )
    await rule.save()


@pytest.mark.asyncio
@pytest.mark.usefixtures("rule_setup")
@pytest.mark.usefixtures("scripts_setup")
async def test_scan():
    snapshot = await Snapshot.all().first().prefetch_related("_scripts__file")
    matcher = RuleMatcher(snapshot)
    results = await matcher.scan()
    assert len(results) == 1
