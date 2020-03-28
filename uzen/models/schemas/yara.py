from typing import List, Optional, Union

from pydantic import BaseModel, Field

from uzen.models.schemas.snapshots import (
    BaseSnapshot,
    CreateSnapshotPayload,
    SearchResult,
)


class ScanPayload(BaseModel):
    source: str = Field(
        None, title="YARA rule", description="String containing the rules code"
    )
    target: str = Field(
        "body",
        title="Target to scan",
        description="Target field to scan (body, whois or certificate)",
    )


class OneshotPayload(CreateSnapshotPayload, ScanPayload):
    pass


class YaraMatch(BaseModel):
    rule: str = Field(None, title="Rule", description="Name of the matching rule")
    namespace: str = Field(
        None, title="Namespace", description="Namespace associated to the matching rule"
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
    strings: List[List[Union[str, int]]] = Field(
        [],
        title="Strings",
        description="List of tuples containing information about the matching strings",
    )


class YaraResult(BaseModel):
    snapshot_id: int = Field(
        None, title="Snapshot ID", description="The ID of a snapshot"
    )
    script_id: Optional[int] = Field(
        None, title="Script ID", description="The ID of a script"
    )
    target: str = Field(None, title="Target", description="The target to scan")
    matches: List[YaraMatch] = Field(
        [], title="YARA matches", description="List of YARA match"
    )


class OneshotResponse(BaseModel):
    snapshot: BaseSnapshot = Field(
        None,
        title="Snapshot model",
        description="Snapshot model without id & created_at fields",
    )
    matched: bool = Field(
        None, title="whether matched or not", description="whether matched or not"
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
