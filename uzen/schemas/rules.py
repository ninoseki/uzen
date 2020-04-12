from uzen.schemas.snapshots import BaseRule, Rule


class CreateRulePayload(BaseRule):
    class Config:
        orm_mode = False
