import datetime

from pydantic import BaseModel, Field

from uzen.schemas.common import Source, Target


class BaseRule(Source, Target):
    """Base Pydantic model for Rule

    Note that this model doesn't have "id" and "created_at" fields.
    """

    name: str = Field(..., title="Name", description="A name of the YARA rule")

    class Config:
        orm_mode = True


class Rule(BaseRule):
    """Full Pydantic model for Rule"""

    id: int
    created_at: datetime.datetime


class CreateRulePayload(BaseRule):
    class Config:
        orm_mode = False
