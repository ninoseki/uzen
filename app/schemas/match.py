from typing import List, Optional, Union
from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import Field

from app.schemas.base import AbstractBaseModel
from app.schemas.mixin import TimestampMixin
from app.schemas.rule import Rule
from app.schemas.script import Script
from app.schemas.search import BaseSearchResults
from app.schemas.snapshot import PlainSnapshot
from app.schemas.yara import YaraMatch


class Match(AbstractBaseModel, TimestampMixin):
    """Pydantic model for Match"""

    matches: List[YaraMatch] = Field(
        ..., title="Matches", description="A list of YARA mastches",
    )
    snapshot: PlainSnapshot = Field(
        ..., title="Snapshot", description="A matched snapshot",
    )
    rule: Rule = Field(
        ..., title="Rule", description="A matched rule",
    )
    script: Optional[Script] = Field(
        None, title="Script", description="A matched script",
    )

    class Config:
        orm_mode = True


class MatchResult(APIModel):
    rule_id: UUID = Field(
        ..., title="Matches", description="An ID of the rule",
    )
    script_id: Optional[UUID] = Field(
        None, title="Matches", description="An ID of the script",
    )
    matches: List[YaraMatch] = Field(
        ..., title="Matches", description="A list of YARA mastches",
    )


class MatchesSearchResults(BaseSearchResults):
    results: Union[List[Match], List[UUID]]
