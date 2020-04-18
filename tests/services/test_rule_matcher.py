import datetime
import uuid

import pytest

from tests.utils import make_snapshot
from uzen.models.rules import Rule
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.services.rule_matcher import RuleMatcher


@pytest.fixture
async def rule_setup(client):
    rule = Rule(
        id=uuid.uuid4(),
        name=f"test",
        target="script",
        source='rule foo: bar {strings: $a = "foo" condition: $a}',
        created_at=datetime.datetime.now(),
    )
    await rule.save()


def snapshot_for_test() -> Snapshot:
    snapshot = make_snapshot()
    snapshot.scripts = [Script(content="foo"), Script(content="bar")]
    return snapshot


@pytest.mark.asyncio
@pytest.mark.usefixtures("rule_setup")
async def test_scan():
    snapshot = snapshot_for_test()

    matcher = RuleMatcher(snapshot)
    results = await matcher.scan()
    assert len(results) == 1
