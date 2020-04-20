from dataclasses import dataclass
from typing import List, Type, Union
from uuid import UUID

from pydantic import BaseModel
from tortoise.models import Model

from uzen.models.classifications import Classification
from uzen.models.dns_records import DnsRecord
from uzen.models.screenshots import Screenshot
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot


@dataclass
class SnapshotResult:
    snapshot: Snapshot
    screenshot: Screenshot


@dataclass
class EnrichmentResults:
    classifications: List[Classification]
    dns_records: List[DnsRecord]
    scripts: List[Script]


@dataclass
class SearchResults:
    results: Union[List[Type[Model]], List[Type[BaseModel]], List[dict], List[UUID]]
    total: int
