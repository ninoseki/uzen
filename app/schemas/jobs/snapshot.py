from datetime import datetime
from typing import Optional
from uuid import UUID

from arq.jobs import JobDef, JobResult
from pydantic import Field

from app.schemas.base import APIModel
from app.schemas.jobs.common import JobStatus
from app.schemas.snapshot import CreateSnapshotPayload


class SnapshotJobResult(APIModel):
    snapshot_id: UUID = Field(...)


class SnapshotJobDefinition(APIModel):
    enqueue_time: datetime
    payload: CreateSnapshotPayload

    @classmethod
    def from_job_definition(cls, job_definition: JobDef) -> "SnapshotJobDefinition":
        payload = job_definition.args[0]
        enqueue_time = job_definition.enqueue_time

        return cls(payload=payload, enqueue_time=enqueue_time)

    @classmethod
    def from_job_result(cls, job_result: JobResult) -> "SnapshotJobDefinition":
        payload = job_result.args[0]
        enqueue_time = job_result.enqueue_time

        return cls(payload=payload, enqueue_time=enqueue_time)


class SnapshotJobStatus(JobStatus):
    result: Optional[SnapshotJobResult] = Field(None)
    definition: SnapshotJobDefinition = Field(...)
