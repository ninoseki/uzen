import datetime
from typing import List

import pytest

from app import models, types
from app.services.scanners import RuleScanner
from app.services.scanners.rule import has_intersection


@pytest.mark.parametrize(
    "list1,list2,expected",
    [
        (["a"], ["b"], False),
        (["a", "c"], ["b"], False),
        (["a", "b"], ["b"], True),
    ],
)
def test_has_intersection(list1: List[str], list2: List[str], expected: bool):
    assert has_intersection(list1, list2) is expected


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


@pytest.fixture
@pytest.mark.usefixtures("client")
async def rule_with_disallowed_network_address():
    rule = models.Rule(
        id=types.ULID(),
        name="test",
        target="script",
        source='rule foo: bar {strings: $a = "foo" condition: $a}',
        disallowed_network_addresses="example.com",
        created_at=datetime.datetime.now(),
    )
    await rule.save()


@pytest.fixture
@pytest.mark.usefixtures("client")
async def rule_with_allowed_network_address():
    rule = models.Rule(
        id=types.ULID(),
        name="test",
        target="script",
        source='rule foo: bar {strings: $a = "foo" condition: $a}',
        allowed_network_addresses="foobar.com",
        created_at=datetime.datetime.now(),
    )
    await rule.save()


@pytest.mark.asyncio
@pytest.mark.usefixtures("rule_setup")
@pytest.mark.usefixtures("scripts")
async def test_scan():
    snapshot = (
        await models.Snapshot.all()
        .first()
        .prefetch_related("scripts__file", "stylesheets__file")
    )
    matcher = RuleScanner(snapshot)
    results = await matcher.scan()
    assert len(results) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("rule_with_disallowed_network_address")
@pytest.mark.usefixtures("scripts")
async def test_scan_with_rule_with_disallowed_network_address():
    snapshot = (
        await models.Snapshot.all()
        .first()
        .prefetch_related("scripts__file", "stylesheets__file")
    )
    matcher = RuleScanner(snapshot)
    results = await matcher.scan()
    # snapshot's hostname is example.com
    # and the registered rule has example.com as a disallowed network address
    assert len(results) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("rule_with_allowed_network_address")
@pytest.mark.usefixtures("scripts")
async def test_scan_with_rule_with_allowed_network_address():
    snapshot = (
        await models.Snapshot.all()
        .first()
        .prefetch_related("scripts__file", "stylesheets__file")
    )
    matcher = RuleScanner(snapshot)
    results = await matcher.scan()
    # snapshot's hostname is example.com
    # and the registered rule has foobar.com as an allowed network address
    assert len(results) == 0
