import pytest
from pydantic import ValidationError

from app.schemas import UpdateRulePayload
from app.schemas.rule import UpdateRulePayload


def test_validation():
    with pytest.raises(ValidationError):
        UpdateRulePayload(source="foo")

    payload = UpdateRulePayload(name="dummy")
    payload.name == "dummy"
