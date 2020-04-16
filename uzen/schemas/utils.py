from dataclasses import dataclass
from typing import List

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
