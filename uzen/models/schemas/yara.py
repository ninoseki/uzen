from typing import List, Union, Optional

from pydantic import AnyHttpUrl, BaseModel, Field

from uzen.models.schemas.classifications import BaseClassification
from uzen.models.schemas.dns_records import BaseDnsRecord
from uzen.models.schemas.scripts import BaseScript
from uzen.models.schemas.snapshots import BaseSnapshot, SearchResult


class ScanPayload(BaseModel):
    source: str = Field(
        None, title="YARA rule", description="String containing the rules code"
    )
    target: str = Field(
        "body",
        title="Target to scan",
        description="Target field to scan (body, whois or certificate)",
    )


class OneshotPayload(ScanPayload):
    url: AnyHttpUrl


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
    scripts: List[BaseScript] = Field(
        None,
        title="Script model",
        description="Script model without id & created_at fields",
    )
    dnsRecords: List[BaseDnsRecord] = Field(
        None,
        title="DNS record model",
        description="DNS record model without id & created_at fields",
    )
    classifications: List[BaseClassification] = Field(
        None,
        title="Classification model",
        description="Classification model without id & created_at fields",
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
