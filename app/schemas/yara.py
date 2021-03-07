from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import Field

from app.schemas.base import APIModel
from app.schemas.common import Source, Target
from app.schemas.snapshot import PlainSnapshot


class YaraScanPayload(Source, Target, APIModel):
    """Playload for YARA scan"""


class YaraMatchString(APIModel):
    """YARA match string"""

    offset: int = Field(...)
    string_identifier: str = Field(...)
    string_data: str = Field(...)


class YaraMatch(APIModel):
    """YARA match"""

    rule: str = Field(..., description="A name of the rule")
    namespace: str = Field(
        ...,
        description="A namespace associated to the matching rule",
    )
    tags: List[str] = Field(
        [],
        description="An array of strings containing the tags associated to the matching rule",
    )
    meta: Dict[str, Any] = Field(
        {},
        description="A dictionary containing metadata associated to the matching rule",
    )
    strings: List[YaraMatchString] = Field(
        [],
        description="A list of tuples containing information about the matching strings",
    )


class YaraResult(APIModel):
    """YARA scan result"""

    snapshot_id: UUID = Field(...)
    script_id: Optional[UUID] = Field(
        ...,
    )
    target: str = Field(..., description="A target to scan")
    matches: List[YaraMatch] = Field([], description="A list of YARA matches")


class YaraScanResult(PlainSnapshot):
    """YARA scan result + snapshot"""

    yara_result: YaraResult = Field(...)

    @classmethod
    def field_keys(cls) -> List[str]:
        keys = list(cls.__fields__.keys())
        keys.remove("yara_result")
        return keys
