from dataclasses import dataclass

from uzen.models.screenshots import Screenshot
from uzen.models.snapshots import Snapshot


@dataclass
class SnapshotResult:
    snapshot: Snapshot
    screenshot: Screenshot
