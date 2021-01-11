from dataclasses import dataclass
from typing import List, Optional, Type, Union
from uuid import UUID

from pydantic import BaseModel
from tortoise.models import Model

from app import models


@dataclass
class ScriptFile:
    script: models.Script
    file: models.File


@dataclass
class SnapshotResult:
    snapshot: models.Snapshot
    screenshot: Optional[bytes]
    script_files: List[ScriptFile]


@dataclass
class EnrichmentResults:
    classifications: List[models.Classification]
    dns_records: List[models.DnsRecord]


@dataclass
class SearchResults:
    results: Union[List[Type[Model]], List[Type[BaseModel]], List[dict], List[UUID]]
    total: int
