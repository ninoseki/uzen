from typing import Optional
from uuid import UUID

from pydantic import Field

from app.schemas.base import APIModel


class Job(APIModel):
    """Job"""

    id: str = Field(...)
    type: str = Field(...)


class SnapshotJobResult(APIModel):
    snapshot_id: UUID = Field(...)


class JobStatus(APIModel):
    id: str = Field(...)
    is_running: bool = Field(...)


class SnapshotJobStatus(JobStatus):
    result: Optional[SnapshotJobResult] = Field(None)
