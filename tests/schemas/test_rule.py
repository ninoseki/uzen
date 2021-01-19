import pytest
from pydantic import ValidationError

from app.schemas.rule import BaseRule, UpdateRulePayload


def test_validation():
    source = 'rule foo: bar {strings: $a = "lmn" condition: $a}'

    with pytest.raises(ValidationError):
        BaseRule(name="", source=source, target="html")

    with pytest.raises(ValidationError):
        BaseRule(name="foo", source="", target="html")

    with pytest.raises(ValidationError):
        BaseRule(name="foo", source=source, target="foo")

    BaseRule(name="foo", source=source, target="html")


def test_update_payload_validation():
    with pytest.raises(ValidationError):
        UpdateRulePayload(source="foo")

    payload = UpdateRulePayload(name="dummy")
    payload.name == "dummy"
