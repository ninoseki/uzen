from typing import List, Optional, Union
from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import Field

from app.schemas.base import AbstractBaseModel
from app.schemas.mixin import TimestampMixin
from app.schemas.script import Script
from app.schemas.search import BaseSearchResults
from app.schemas.snapshot import PlainSnapshot, Rule
from app.schemas.yara import YaraMatch


class Match(AbstractBaseModel, TimestampMixin):
    """Match"""

    matches: List[YaraMatch] = Field(
        ...,
        description="A list of YARA matches",
    )
    snapshot: PlainSnapshot = Field(
        ...,
        description="A matched snapshot",
    )
    rule: Rule = Field(
        ...,
        description="A matched rule",
    )
    script: Optional[Script] = Field(
        None,
        description="A matched script",
    )

    class Config:
        orm_mode = True


class MatchResult(APIModel):
    """Match result"""

    rule_id: UUID = Field(
        ...,
        description="An ID of the rule",
    )
    script_id: Optional[UUID] = Field(
        None,
        description="An ID of the script",
    )
    matches: List[YaraMatch] = Field(
        ...,
        title="Matches",
        description="A list of YARA matches",
    )


class MatchesSearchResults(BaseSearchResults):
    results: Union[List[Match], List[UUID]]
