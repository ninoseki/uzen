from dataclasses import dataclass
from typing import List, Type, Union
from uuid import UUID

from pydantic import BaseModel, Field
from tortoise.models import Model

from uzen.models.classifications import Classification
from uzen.models.dns_records import DnsRecord
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot


@dataclass
class SnapshotResult:
    snapshot: Snapshot
    screenshot: bytes
    scripts: List[Script]


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
