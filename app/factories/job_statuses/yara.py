from typing import List, Optional, cast

from arq.connections import ArqRedis

from app import schemas
from app.factories.job_statuses.utils import get_job_definition_and_result


class YaraScanJobStatusFactory:
    @staticmethod
    async def from_job_id(
        arq_redis: ArqRedis, job_id: str
    ) -> schemas.YaraScanJobStatus:
        job_definition: Optional[schemas.YaraScanJobDefinition] = None
        job_result: Optional[schemas.YaraScanJobResult] = None

        is_running, job_definition_, job_result_ = await get_job_definition_and_result(
            arq_redis=arq_redis, job_id=job_id
        )

        if job_definition_ is not None:
            job_definition = schemas.YaraScanJobDefinition.from_job_definition(
                job_definition_
            )

        if job_result_ is not None:
            result = cast(schemas.JobResultWrapper, job_result_.result)
            scan_results = cast(List[schemas.YaraScanJobResult], result.result or [])
            job_result = schemas.YaraScanJobResult(scan_results=scan_results)
            job_definition = schemas.YaraScanJobDefinition.from_job_result(job_result_)

        return schemas.YaraScanJobStatus(
            id=job_id,
            is_running=is_running,
            result=job_result,
            definition=job_definition,
        )
