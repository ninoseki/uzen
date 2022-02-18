from typing import Optional, Tuple, cast

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
        try:
            if result.error is not None:
                raise JobExecutionError(result.error)
        except AttributeError:
            # then someting went wrong with the job...
            # e.g. result=AttributeError("'dict' object has no attribute 'asn'")
            raise JobExecutionError(str(result))

    return is_running, job_definition, job_result
