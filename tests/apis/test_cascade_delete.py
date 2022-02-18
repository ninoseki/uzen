import asyncio
from typing import List

from fastapi.testclient import TestClient

from app import models
from tests.helper import (
    count_all_matches,
    count_all_rules,
    count_all_scripts,
    count_all_snapshots,
)


def test_delete_snapshot_with_scripts(
    client: TestClient,
    event_loop: asyncio.AbstractEventLoop,
    scripts: List[models.Script],
    snapshots: List[models.Snapshot],
):
    id_ = snapshots[0].id

    response = client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert count_all_snapshots(event_loop) == len(snapshots) - 1
    assert count_all_scripts(event_loop) == len(scripts) - 1


def test_delete_snapshot_with_matches(
    client: TestClient,
    event_loop: asyncio.AbstractEventLoop,
    matches: List[models.Match],
    snapshots: List[models.Snapshot],
):
    id_ = snapshots[0].id
    response = client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert count_all_snapshots(event_loop) == len(snapshots) - 1
    assert count_all_matches(event_loop) == len(matches) - 1


def test_delete_rule_with_matches(
    client: TestClient,
    event_loop: asyncio.AbstractEventLoop,
    matches: List[models.Match],
    rules: List[models.Rule],
):
    id_ = rules[0].id

    response = client.delete(f"/api/rules/{id_}")
    assert response.status_code == 204

    assert count_all_rules(event_loop) == len(rules) - 1
    assert count_all_matches(event_loop) == len(matches) - 1
