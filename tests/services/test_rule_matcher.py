import datetime
import uuid

import pytest

from app.models.rule import Rule
from app.models.snapshot import Snapshot
from app.services.rule_matcher import RuleMatcher


@pytest.fixture
@pytest.mark.usefixtures("client")
async def rule_setup():
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
