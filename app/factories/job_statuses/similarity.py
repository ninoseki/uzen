from typing import List, Optional, cast

from arq.connections import ArqRedis

from app import schemas
from app.factories.job_statuses.utils import get_job_definition_and_result


class SimilarityScanJobStatusFactory:
    @staticmethod
    async def from_job_id(
        arq_redis: ArqRedis, job_id: str
    ) -> schemas.SimilarityScanJobStatus:
        job_definition: Optional[schemas.SimilarityScanJobDefinition] = None
        job_result: Optional[schemas.SimilarityScanJobResult] = None

        is_running, job_definition_, job_result_ = await get_job_definition_and_result(
            arq_redis=arq_redis, job_id=job_id
        )

        if job_definition_ is not None:
            job_definition = schemas.SimilarityScanJobDefinition.from_job_definition(
                job_definition_
            )

        if job_result_ is not None:
            result = cast(schemas.JobResultWrapper, job_result_.result)
            scan_results = cast(
                List[schemas.SimilarityScanJobResult], result.result or []
            )
            job_result = schemas.SimilarityScanJobResult(scan_results=scan_results)
            job_definition = schemas.SimilarityScanJobDefinition.from_job_result(
                job_result_
            )

        return schemas.SimilarityScanJobStatus(
            id=job_id,
            is_running=is_running,
            result=job_result,
            definition=job_definition,
        )
