import asyncio

import pytest
from fastapi.testclient import TestClient

from tests.helper import (
    count_all_matches,
    count_all_rules,
    count_all_scripts,
    count_all_snapshots,
    first_rule_id_sync,
    first_snapshot_id_sync,
)


@pytest.mark.usefixtures("scripts_setup")
def test_delete_snapshot_with_scripts(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    id_ = first_snapshot_id_sync(event_loop)
    snapshot_count = count_all_snapshots(event_loop)
    script_count = count_all_scripts(event_loop)

    response = client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert count_all_snapshots(event_loop) == snapshot_count - 1
    assert count_all_scripts(event_loop) == script_count - 1


@pytest.mark.usefixtures("matches_setup")
def test_delete_snapshot_with_matches(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    id_ = first_snapshot_id_sync(event_loop)
    snapshot_count = count_all_snapshots(event_loop)
    match_count = count_all_matches(event_loop)

    response = client.delete(f"/api/snapshots/{id_}")
    assert response.status_code == 204

    assert count_all_snapshots(event_loop) == snapshot_count - 1
    assert count_all_matches(event_loop) == match_count - 1


@pytest.mark.usefixtures("matches_setup")
def test_delete_rule_with_matches(
    client: TestClient, event_loop: asyncio.AbstractEventLoop
):
    id_ = first_rule_id_sync(event_loop)
    rule_count = count_all_rules(event_loop)
    match_count = count_all_matches(event_loop)

    response = client.delete(f"/api/rules/{id_}")
    assert response.status_code == 204

    assert count_all_rules(event_loop) == rule_count - 1
    assert count_all_matches(event_loop) == match_count - 1
