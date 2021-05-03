from typing import Optional, cast

from arq.connections import ArqRedis

from app import schemas
from app.factories.job_statuses.utils import get_job_definition_and_result


class SnapshotJobStatusFactory:
    @staticmethod
    async def from_job_id(
        arq_redis: ArqRedis, job_id: str
    ) -> schemas.SnapshotJobStatus:
        job_definition: Optional[schemas.SnapshotJobDefinition] = None
        job_result: Optional[schemas.SnapshotJobResult] = None

        is_running, job_definition_, job_result_ = await get_job_definition_and_result(
            arq_redis=arq_redis, job_id=job_id
        )

        if job_definition_ is not None:
            job_definition = schemas.SnapshotJobDefinition.from_job_definition(
                job_definition_
            )

        if job_result_ is not None:
            result = cast(schemas.JobResultWrapper, job_result_.result)
            job_result = schemas.SnapshotJobResult.parse_obj(result.result or {})
            job_definition = schemas.SnapshotJobDefinition.from_job_result(job_result_)

        return schemas.SnapshotJobStatus(
            id=job_id,
            is_running=is_running,
            result=job_result,
            definition=job_definition,
        )
