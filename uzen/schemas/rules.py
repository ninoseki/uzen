import datetime

from pydantic import BaseModel, Field, validator

from uzen.schemas.common import Source, Target


class BaseRule(BaseModel):
    """Base Pydantic model for Rule

    Note that this model doesn't have "id" and "created_at" fields.
    """

    name: str
    target: str
    source: str

    class Config:
        orm_mode = True


class Rule(BaseRule):
    """Full Pydantic model for Rule"""

    id: int
    created_at: datetime.datetime


class CreateRulePayload(Source, Target):
    name: str = Field(..., title="Name of YARA rule", description="Name of a YARA rule")
