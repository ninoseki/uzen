from typing import List, Optional
from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import Field

from app.schemas.common import Source, Target
from app.schemas.snapshots import SimplifiedSnapshot


class YaraScanPayload(Source, Target, APIModel):
    pass


class YaraMatchString(APIModel):
    offset: int
    string_identifier: str
    string_data: str


class YaraMatch(APIModel):
    rule: str = Field(..., title="Rule", description="A name of the rule")
    namespace: str = Field(
        ...,
        title="Namespace",
        description="A namespace associated to the matching rule",
    )
    tags: List[str] = Field(
        [],
        title="Tags",
        description="An array of strings containig the tags associated to the matching rule",
    )
    meta: dict = Field(
        {},
        title="Meta",
        description="A dictionary containing metadata associated to the matching rule",
    )
    strings: List[YaraMatchString] = Field(
        [],
        title="Strings",
        description="A list of tuples containing information about the matching strings",
    )


class YaraResult(APIModel):
    snapshot_id: UUID = Field(
        ..., title="Snapshot ID", description="An ID of the snapshot"
    )
    script_id: Optional[UUID] = Field(
        ..., title="Script ID", description="An ID of the script"
    )
    target: str = Field(..., title="Target", description="The target to scan")
    matches: List[YaraMatch] = Field(
        [], title="YARA matches", description="A list of YARA matches"
    )


class YaraScanResult(SimplifiedSnapshot):
    """Simplified version of Pydantic model of Snapshot"""

    yara_result: YaraResult

    @classmethod
    def field_keys(cls) -> List[str]:
        keys = list(cls.__fields__.keys())
        keys.remove("yara_result")
        return keys
