from typing import List, Optional

from pydantic import Field

from app.schemas.base import AbstractBaseModel, APIModel
from app.schemas.mixin import TimestampMixin
from app.schemas.script import Script
from app.schemas.search import BaseSearchResults
from app.schemas.snapshot import PlainSnapshot, Rule
from app.schemas.yara import YaraMatch
from app.types import ULID


class Match(AbstractBaseModel, TimestampMixin):
    """Match"""

    matches: List[YaraMatch] = Field(
        ...,
        description="A list of YARA matches",
    )
    snapshot: PlainSnapshot = Field(
        ...,
    )
    rule: Rule = Field(
        ...,
    )
    script: Optional[Script] = Field(
        None,
    )

    class Config:
        orm_mode = True


class MatchResult(APIModel):
    """Match result"""

    rule_id: ULID = Field(
        ...,
    )
    script_id: Optional[ULID] = Field(
        None,
    )
    matches: List[YaraMatch] = Field(
        ...,
        title="Matches",
        description="A list of YARA matches",
    )


class MatchesSearchResults(BaseSearchResults):
    results: List[Match]
