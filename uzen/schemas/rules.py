from uzen.schemas.snapshots import BaseRule, Rule  # noqa: F401


class CreateRulePayload(BaseRule):
    class Config:
        orm_mode = False
