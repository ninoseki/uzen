from typing import Optional

import pytest
from pydantic import ValidationError

from app.schemas.rule import UpdateRulePayload
from app.schemas.snapshot import BaseRule

source = 'rule foo: bar {strings: $a = "lmn" condition: $a}'


@pytest.mark.parametrize(
    "name,source,target,error",
    [
        ("", source, "html", ValidationError),
        ("foo", "", "html", ValidationError),
        ("foo", source, "foo", ValidationError),
        ("foo", source, "html", None),
    ],
)
def test_validation(name: str, source: str, target: str, error):
    if error is not None:
        with pytest.raises(error):
            BaseRule(name=name, source=source, target=target)
    else:
        rule = BaseRule(name=name, source=source, target=target)
        assert rule.name == name
        assert rule.source == source
        assert rule.target == target


@pytest.mark.parametrize(
    "name,source,target,error",
    [
        (None, "foo", None, ValidationError),
        (None, None, "foo", ValidationError),
        ("foo", None, None, None),
    ],
)
def test_update_payload_validation(
    name: Optional[str], source: Optional[str], target: Optional[str], error
):
    input = {"name": name, "source": source, "target": target}

    if error is not None:
        with pytest.raises(error):
            UpdateRulePayload.parse_obj(input)
    else:
        UpdateRulePayload.parse_obj(input)
