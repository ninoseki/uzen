import json

import pytest

from uzen.models.rules import Rule


@pytest.mark.asyncio
async def test_create_rule_with_invalid_target(client):
    payload = {"name": "test", "target": "foo", "source": "foo"}
    response = await client.post("/api/rules/", data=json.dumps(payload))
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_rule_with_invalid_source(client):
    payload = {"name": "test", "target": "body", "source": "foo; bar;"}
    response = await client.post("/api/rules/", data=json.dumps(payload))
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_rule(client):
    payload = {
        "name": "test",
        "target": "body",
        "source": 'rule foo: bar {strings: $a = "lmn" condition: $a}',
    }
    response = await client.post("/api/rules/", data=json.dumps(payload))
    assert response.status_code == 201

    rules = await Rule.all()
    assert len(rules) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("rules_setup")
async def test_delete_rule(client):
    response = await client.delete("/api/rules/1")
    assert response.status_code == 204


@pytest.mark.asyncio
@pytest.mark.usefixtures("rules_setup")
async def test_rules_search(client):
    response = await client.get("/api/rules/search")
    assert response.status_code == 200

    rules = response.json()
    assert len(rules) == 5

    response = await client.get("/api/rules/search", params={"name": "test1"})
    rules = response.json()
    assert len(rules) == 1

    response = await client.get("/api/rules/search", params={"target": "body"})
    rules = response.json()
    assert len(rules) == 5

    response = await client.get("/api/rules/search", params={"source": "lmn"})
    rules = response.json()
    assert len(rules) == 5


@pytest.mark.asyncio
@pytest.mark.usefixtures("rules_setup")
async def test_rules_count(client):
    response = await client.get("/api/rules/count")
    assert response.status_code == 200

    data = response.json()
    count = data.get("count")
    assert isinstance(count, int)
    assert count == 5


@pytest.mark.asyncio
@pytest.mark.usefixtures("rules_setup")
async def test_update(client):
    payload = {"name": "woweee"}
    response = await client.put("/api/rules/1", data=json.dumps(payload))
    assert response.status_code == 200

    rule = await Rule.get(id=1)
    assert rule.name == "woweee"

    payload = {
        "name": "test",
        "target": "script",
        "source": 'rule foo: bar {strings: $a = "html" condition: $a}',
    }
    response = await client.put("/api/rules/1", data=json.dumps(payload))
    assert response.status_code == 200

    rule = await Rule.get(id=1)
    assert rule.name == "test"
    assert rule.target == "script"
    assert rule.source == 'rule foo: bar {strings: $a = "html" condition: $a}'
