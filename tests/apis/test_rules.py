import asyncio
from typing import List

from fastapi.testclient import TestClient

from app import models
from app.models.rule import Rule
from tests.helper import count_all_rules


def test_create_rule_with_invalid_target(client: TestClient):
    payload = {"name": "test", "target": "foo", "source": "foo"}
    response = client.post("/api/rules/", json=payload)
    assert response.status_code == 422


def test_create_rule_with_invalid_source(client: TestClient):
    payload = {"name": "test", "target": "html", "source": "foo; bar;"}
    response = client.post("/api/rules/", json=payload)
    assert response.status_code == 422


def test_create_rule(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    payload = {
        "name": "test",
        "target": "html",
        "source": 'rule foo: bar {strings: $a = "lmn" condition: $a}',
    }
    response = client.post("/api/rules/", json=payload)
    assert response.status_code == 201

    count = count_all_rules(event_loop)
    assert count == 1


def test_delete_rule(
    client: TestClient, event_loop: asyncio.AbstractEventLoop, rules: List[models.Rule]
):
    id_ = rules[0].id
    response = client.delete(f"/api/rules/{id_}")
    assert response.status_code == 204


def test_rules_search(
    client: TestClient, event_loop: asyncio.AbstractEventLoop, rules: List[models.Rule]
):
    count = len(rules)

    response = client.get("/api/rules/search")
    data = response.json()
    rules = data.get("results")
    assert len(rules) == count

    # it matches with a rule
    response = client.get("/api/rules/search", params={"name": "test1"})
    data = response.json()
    rules = data.get("results")
    assert len(rules) == 1

    # it matches with the all rules
    response = client.get("/api/rules/search", params={"target": "html"})
    data = response.json()
    rules = data.get("results")
    assert len(rules) == count

    # it matches with the all rules
    response = client.get("/api/rules/search", params={"source": "lmn"})
    data = response.json()
    rules = data.get("results")
    assert len(rules) == count


def test_update(
    client: TestClient, event_loop: asyncio.AbstractEventLoop, rules: List[models.Rule]
):
    id_ = rules[0].id

    payload = {"name": "woweee"}
    response = client.put(f"/api/rules/{id_}", json=payload)
    assert response.status_code == 200

    rule = event_loop.run_until_complete(Rule.get(id=id_))
    assert rule.name == "woweee"
    old_updated_at = rule.updated_at

    payload = {
        "name": "test",
        "target": "script",
        "source": 'rule foo: bar {strings: $a = "html" condition: $a}',
    }
    response = client.put(f"/api/rules/{id_}", json=payload)
    assert response.status_code == 200

    rule = event_loop.run_until_complete(Rule.get(id=id_))
    assert rule.name == "test"
    assert rule.target == "script"
    assert rule.source == 'rule foo: bar {strings: $a = "html" condition: $a}'
    # should update updated_at field
    assert old_updated_at < rule.updated_at
