from typing import List, Literal, Optional, Union
from uuid import UUID

import yara
from fastapi_utils.api_model import APIModel
from pydantic import Field, validator

from app.schemas.search import BaseSearchResults
from app.schemas.snapshot import BaseRule, Rule  # noqa: F401


class CreateRulePayload(BaseRule):
    pass


class UpdateRulePayload(APIModel):
    name: Optional[str] = Field(
        None, title="Name", description="A name of the YARA rule"
    )
    source: Optional[str] = Field(
        None,
        title="YARA rule",
        description="String containing the rules code",
    )
    target: Optional[Literal["html", "certificate", "script", "whois"]] = Field(
        title="Target",
        description="A target field to scan (html, certificate, script or whois)",
    )

    @validator("source")
    def source_compilable(cls, v):
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
    results: Union[List[Rule], List[UUID]]
