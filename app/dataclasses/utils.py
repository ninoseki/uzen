from dataclasses import dataclass, field
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
    html: models.HTML
    whois: Optional[models.Whois] = None
    certificate: Optional[models.Certificate] = None
    screenshot: Optional[bytes] = None
    har: Optional[models.HAR] = None
    script_files: List[ScriptFile] = field(default_factory=lambda: [])


@dataclass
class EnrichmentResults:
    classifications: List[models.Classification]
    dns_records: List[models.DnsRecord]


@dataclass
class SearchResults:
    results: Union[List[Type[Model]], List[Type[BaseModel]], List[dict], List[UUID]]
    total: int
