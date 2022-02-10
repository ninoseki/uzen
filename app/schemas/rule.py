from typing import List, Optional

import yara
from pydantic import Field, validator

from app.schemas.base import APIModel
from app.schemas.search import BaseSearchResults
from app.schemas.snapshot import BaseRule, Rule
from app.schemas.types import TargetTypes


class CreateRulePayload(BaseRule):
    """Payload to create a rule"""


class UpdateRulePayload(BaseRule):
    """Payload to update a rule"""

    name: Optional[str] = Field(None, description="A name of the YARA rule")
    source: Optional[str] = Field(
        None,
        title="YARA rule",
        description="A string containing the YARA rule code",
    )
    target: Optional[TargetTypes] = Field(
        description="A target field to scan (html, certificate, script or whois)",
    )

    @validator("source")
    def source_compilable(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v

        try:
            yara.compile(source=v)
        except yara.Error as e:
            raise ValueError(f"YARA compile error: {str(e)}")
        return v

    class Config:
        orm_mode = False


class RulesSearchResults(BaseSearchResults):
    results: List[Rule] = Field(...)


class RuleSearchFilters(APIModel):
    name: Optional[str] = Field(None)
    target: Optional[str] = Field(None)
    source: Optional[str] = Field(None)
