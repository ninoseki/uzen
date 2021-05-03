from typing import List, Optional, Tuple, cast

from arq.connections import ArqRedis
from arq.constants import job_key_prefix, result_key_prefix
from arq.jobs import DeserializationError, JobDef, JobResult

from app import schemas
from app.core.exceptions import JobExecutionError, JobNotFoundError


async def is_exists(arq_redis: ArqRedis, key: str) -> bool:
    return await arq_redis.exists(key) == 1


async def is_running_job(arq_redis: ArqRedis, id: str) -> bool:
    key = job_key_prefix + id
    return await is_exists(arq_redis=arq_redis, key=key)


async def is_finished_job(arq_redis: ArqRedis, id: str) -> bool:
    key = result_key_prefix + id
    return await is_exists(arq_redis=arq_redis, key=key)


async def get_job_definition(arq_redis: ArqRedis, id: str) -> JobDef:
    return await arq_redis._get_job_def(id, 0)


async def get_result(arq_redis: ArqRedis, id: str) -> JobResult:
    key = result_key_prefix + id
    return await arq_redis._get_job_result(key)


async def get_job_definition_and_result(
    arq_redis: ArqRedis,
    job_id: str,
) -> Tuple[bool, Optional[JobDef], Optional[JobResult]]:
    job_definition: Optional[JobDef] = None
    is_running: bool = True
    try:
        job_definition = await get_job_definition(arq_redis=arq_redis, id=job_id)
    except (KeyError, DeserializationError):
        is_running = False

    job_result: Optional[JobResult] = None
    if not is_running:
        try:
            job_result = await get_result(arq_redis=arq_redis, id=job_id)
        except (KeyError):
            raise JobNotFoundError(f"{job_id} is not found")

        result = cast(schemas.JobResultWrapper, job_result.result)

        # check error
        if result.error is not None:
            raise JobExecutionError(result.error)

    return is_running, job_definition, job_result


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
