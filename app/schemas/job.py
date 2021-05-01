from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID

from arq.jobs import JobDef, JobResult
from pydantic import Field

from app.schemas.base import APIModel
from app.schemas.similarity import SimilarityScanPayloadWithSearchOptions
from app.schemas.snapshot import CreateSnapshotPayload, PlainSnapshot
from app.schemas.yara import YaraScanPayloadWithSearchOptions, YaraScanResult


class Job(APIModel):
    """Job"""

    id: str = Field(...)
    type: str = Field(...)


class JobStatus(APIModel):
    id: str = Field(...)
    is_running: bool = Field(...)


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


class YaraScanJobDefinition(APIModel):
    enqueue_time: datetime
    payload: YaraScanPayloadWithSearchOptions

    @classmethod
    def from_job_definition(cls, job_definition: JobDef) -> "YaraScanJobDefinition":
        payload = job_definition.args[0]
        enqueue_time = job_definition.enqueue_time

        return cls(payload=payload, enqueue_time=enqueue_time)

    @classmethod
    def from_job_result(cls, job_result: JobResult) -> "YaraScanJobDefinition":
        payload = job_result.args[0]
        enqueue_time = job_result.enqueue_time

        return cls(payload=payload, enqueue_time=enqueue_time)


class YaraScanJobResult(APIModel):
    scan_results: List[YaraScanResult] = Field(...)


class YaraScanJobStatus(JobStatus):
    result: Optional[YaraScanJobResult] = Field(None)
    definition: YaraScanJobDefinition = Field(...)


class SimilarityScanJobDefinition(APIModel):
    enqueue_time: datetime
    payload: SimilarityScanPayloadWithSearchOptions

    @classmethod
    def from_job_definition(
        cls, job_definition: JobDef
    ) -> "SimilarityScanJobDefinition":
        payload = job_definition.args[0]
        enqueue_time = job_definition.enqueue_time

        return cls(payload=payload, enqueue_time=enqueue_time)

    @classmethod
    def from_job_result(cls, job_result: JobResult) -> "SimilarityScanJobDefinition":
        payload = job_result.args[0]
        enqueue_time = job_result.enqueue_time

        return cls(payload=payload, enqueue_time=enqueue_time)


class SimilarityScanJobResult(APIModel):
    scan_results: List[PlainSnapshot] = Field(...)


class SimilarityScanJobStatus(JobStatus):
    result: Optional[SimilarityScanJobResult] = Field(None)
    definition: SimilarityScanJobDefinition = Field(...)


class JobResultWrapper(APIModel):
    result: Optional[Any] = Field(None)
    error: Optional[str] = Field(None)
