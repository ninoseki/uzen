from dataclasses import dataclass
from typing import List, Optional, Type, Union
from uuid import UUID

from pydantic import BaseModel, Field
from tortoise.models import Model

from app.models.classifications import Classification
from app.models.dns_records import DnsRecord
from app.models.scripts import File, Script
from app.models.snapshots import Snapshot


@dataclass
class ScriptFile:
    script: Script
    file: File


@dataclass
class SnapshotResult:
    snapshot: Snapshot
    screenshot: Optional[bytes]
    script_files: List[ScriptFile]


@dataclass
class EnrichmentResults:
    classifications: List[Classification]
    dns_records: List[DnsRecord]


@dataclass
class SearchResults:
    results: Union[List[Type[Model]], List[Type[BaseModel]], List[dict], List[UUID]]
    total: int


class CountResponse(BaseModel):
    count: int = Field(
        ..., title="Count", description="Total count of existing items",
    )