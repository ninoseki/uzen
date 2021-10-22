import datetime

import pytest

from app import models, types
from app.services.scanners import RuleScanner


@pytest.fixture
@pytest.mark.usefixtures("client")
async def rule_setup():
    rule = models.Rule(
        id=types.ULID(),
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
    snapshot = await models.Snapshot.all().first().prefetch_related("_scripts__file")
    matcher = RuleScanner(snapshot)
    results = await matcher.scan()
    assert len(results) == 1
