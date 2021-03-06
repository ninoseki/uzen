from typing import List, Optional, Union
from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import Field

from uzen.schemas.base import AbstractBaseModel
from uzen.schemas.mixins import TimestampMixin
from uzen.schemas.rules import Rule
from uzen.schemas.scripts import Script
from uzen.schemas.search import BaseSearchResults
from uzen.schemas.snapshots import Snapshot
from uzen.schemas.yara import YaraMatch


class BaseMatch(APIModel):
    """Base Pydantic model for Match

    Note that this model doesn't have "id" and "created_at" fields.
    """

    matches: List[YaraMatch] = Field(
        ..., title="Matches", description="A list of YARA mastches",
    )
    snapshot: Snapshot = Field(
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


class Match(BaseMatch, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for Match"""


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


class SearchResults(BaseSearchResults):
    results: Union[List[Match], List[UUID]]
