from typing import List
import datetime

from pydantic import BaseModel

from uzen.models.schemas.rules import Rule
from uzen.models.schemas.snapshots import Snapshot
from uzen.models.schemas.yara import YaraMatch


class BaseMatch(BaseModel):
    """Base Pydantic model for Match

    Note that this model doesn't have "id" and "created_at" fields.
    """

    matches: List[YaraMatch]
    snapshot: Snapshot
    rule: Rule

    class Config:
        orm_mode = True


class Match(BaseMatch):
    """Full Pydantic model for Match"""

    id: int
    created_at: datetime.datetime


class MatchResult(BaseModel):
    rule_id: int
    matches: List[YaraMatch]
