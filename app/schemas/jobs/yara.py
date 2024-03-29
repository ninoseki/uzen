from datetime import datetime
from typing import List, Optional

from arq.jobs import JobDef, JobResult
from pydantic import Field

from app.schemas.base import APIModel
from app.schemas.jobs.common import JobStatus
from app.schemas.yara import YaraScanResult, YaraScanWithSearchOptions


class YaraScanJobDefinition(APIModel):
    enqueue_time: datetime
    payload: YaraScanWithSearchOptions

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
