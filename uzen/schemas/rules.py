from typing import Optional

from pydantic import BaseModel, Field, validator

from uzen.schemas.snapshots import BaseRule, Rule  # noqa: F401


class CreateRulePayload(BaseRule):
    class Config:
        orm_mode = False


class UpdateRulePayload(BaseModel):
    name: Optional[str] = Field(
        None, title="Name", description="A name of the YARA rule"
    )
    source: Optional[str] = Field(
        None, title="YARA rule", description="String containing the rules code",
    )
    target: Optional[str] = Field(
        None,
        title="Target",
        description="A target field to scan (body, certificate, script or whois)",
    )

    @validator("target")
    def target_types(cls, v):
        if v not in ["body", "certificate", "script", "whois", None]:
            raise ValueError("Target must be any of body, certificate, script or whois")
        return v

    class Config:
        orm_mode = False
