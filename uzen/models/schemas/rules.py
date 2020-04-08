import datetime

from pydantic import BaseModel, Field, validator
import yara


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


class CreateRulePayload(BaseModel):
    name: str = Field(
        None, title="Name of YARA rule", description="Name of a YARA rule"
    )
    source: str = Field(
        None, title="YARA rule", description="String containing the rules code"
    )
    target: str = Field(
        "body",
        title="Target to scan",
        description="Target field to scan (body, whois or certificate)",
    )

    @validator("target")
    def target_types(cls, v):
        if v not in ["body", "certificate", "script", "whois"]:
            raise ValueError("must be any of body, certificate, script or whois")
        return v

    @validator("source")
    def source_compilable(cls, v):
        try:
            yara.compile(source=v)
        except yara.Error as e:
            raise ValueError(str(e))
        return v
