import json

import httpx
import pytest

from app.models.rule import Rule
from tests.helper import first_rule_id


@pytest.mark.asyncio
async def test_create_rule_with_invalid_target(client: httpx.AsyncClient):
    payload = {"name": "test", "target": "foo", "source": "foo"}
    response = await client.post("/api/rules/", data=json.dumps(payload))
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_rule_with_invalid_source(client: httpx.AsyncClient):
    payload = {"name": "test", "target": "html", "source": "foo; bar;"}
    response = await client.post("/api/rules/", data=json.dumps(payload))
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_rule(client: httpx.AsyncClient):
    payload = {
        "name": "test",
        "target": "html",
        "source": 'rule foo: bar {strings: $a = "lmn" condition: $a}',
    }
    response = await client.post("/api/rules/", data=json.dumps(payload))
    assert response.status_code == 201

    count = await Rule.all().count()
    assert count == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("rules_setup")
async def test_delete_rule(client: httpx.AsyncClient):
    id_ = await first_rule_id()
    response = await client.delete(f"/api/rules/{id_}")
    assert response.status_code == 204


@pytest.mark.asyncio
@pytest.mark.usefixtures("rules_setup")
async def test_rules_search(client: httpx.AsyncClient):
    count = await Rule.all().count()

    response = await client.get("/api/rules/search")
    json = response.json()
    rules = json.get("results")
    assert len(rules) == count

    # it matches with a rule
    response = await client.get("/api/rules/search", params={"name": "test1"})
    json = response.json()
    rules = json.get("results")
    assert len(rules) == 1

    # it matches with the all rules
    response = await client.get("/api/rules/search", params={"target": "html"})
    json = response.json()
    rules = json.get("results")
    assert len(rules) == count

    # it matches with the all rules
    response = await client.get("/api/rules/search", params={"source": "lmn"})
    json = response.json()
    rules = json.get("results")
    assert len(rules) == count


@pytest.mark.asyncio
@pytest.mark.usefixtures("rules_setup")
async def test_update(client: httpx.AsyncClient):
    id_ = await first_rule_id()

    payload = {"name": "woweee"}
    response = await client.put(f"/api/rules/{id_}", data=json.dumps(payload))
    assert response.status_code == 200

    rule = await Rule.get(id=id_)
    assert rule.name == "woweee"
    old_updated_at = rule.updated_at

    payload = {
        "name": "test",
        "target": "script",
        "source": 'rule foo: bar {strings: $a = "html" condition: $a}',
    }
    response = await client.put(f"/api/rules/{id_}", data=json.dumps(payload))
    assert response.status_code == 200

    rule = await Rule.get(id=id_)
    assert rule.name == "test"
    assert rule.target == "script"
    assert rule.source == 'rule foo: bar {strings: $a = "html" condition: $a}'
    # should update updated_at field
    assert old_updated_at < rule.updated_at
