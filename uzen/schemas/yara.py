from typing import List, Optional

from pydantic import BaseModel, Field

from uzen.schemas.common import Source, Target
from uzen.schemas.snapshots import (
    BaseSnapshot,
    CreateSnapshotPayload,
    SearchResult,
)


class ScanPayload(Source, Target):
    pass


class OneshotPayload(CreateSnapshotPayload, ScanPayload):
    pass


class YaraMatchString(BaseModel):
    offset: int
    string_identifier: str
    string_data: str


class YaraMatch(BaseModel):
    rule: str = Field(..., title="Rule", description="Name of the matching rule")
    namespace: str = Field(
        ..., title="Namespace", description="Namespace associated to the matching rule"
    )
    tags: List[str] = Field(
        [],
        title="Tags",
        description="Array of strings containig the tags associated to the matching rule",
    )
    meta: dict = Field(
        {},
        title="Meta",
        description="Dictionary containing metadata associated to the matching rule",
    )
    strings: List[YaraMatchString] = Field(
        [],
        title="Strings",
        description="List of tuples containing information about the matching strings",
    )


class YaraResult(BaseModel):
    snapshot_id: int = Field(
        ..., title="Snapshot ID", description="The ID of a snapshot"
    )
    script_id: Optional[int] = Field(
        ..., title="Script ID", description="The ID of a script"
    )
    target: str = Field(..., title="Target", description="The target to scan")
    matches: List[YaraMatch] = Field(
        [], title="YARA matches", description="List of YARA match"
    )


class OneshotResponse(BaseModel):
    snapshot: BaseSnapshot = Field(
        ...,
        title="Snapshot model",
        description="Snapshot model without id & created_at fields",
    )
    matched: bool = Field(
        ..., title="whether matched or not", description="whether matched or not"
    )
    matches: List[YaraMatch] = Field(
        [], title="YARA matches", description="YARA matches"
    )


class ScanResult(SearchResult):
    """Simplified version of Pydantic model of Snapshot"""

    yara_result: YaraResult

    @classmethod
    def field_keys(cls) -> List[str]:
        keys = list(cls.__fields__.keys())
        keys.remove("yara_result")
        return keys
