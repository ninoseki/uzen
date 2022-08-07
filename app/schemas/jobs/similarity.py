from datetime import datetime
from typing import List, Optional

from arq.jobs import JobDef, JobResult
from pydantic import Field

from app.schemas.base import APIModel
from app.schemas.jobs.common import JobStatus
from app.schemas.similarity import SimilarityScanResult, SimilarityScanWithSearchOptions


class SimilarityScanJobDefinition(APIModel):
    enqueue_time: datetime
    payload: SimilarityScanWithSearchOptions

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
    scan_results: List[SimilarityScanResult] = Field(...)


class SimilarityScanJobStatus(JobStatus):
    result: Optional[SimilarityScanJobResult] = Field(None)
    definition: SimilarityScanJobDefinition = Field(...)
