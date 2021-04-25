from typing import List, Optional, cast

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


class SnapshotJobStatusFactory:
    @staticmethod
    async def from_job_id(
        arq_redis: ArqRedis, job_id: str
    ) -> schemas.SnapshotJobStatus:
        job_definition: Optional[schemas.SnapshotJobDefinition] = None
        is_running: bool = True
        try:
            job_definition_ = await get_job_definition(arq_redis=arq_redis, id=job_id)
            job_definition = schemas.SnapshotJobDefinition.from_job_definition(
                job_definition_
            )
        except (KeyError, DeserializationError):
            is_running = False

        job_result: Optional[JobResult] = None
        snapshot_job_result: Optional[schemas.SnapshotJobResult] = None
        if not is_running:
            try:
                job_result = await get_result(arq_redis=arq_redis, id=job_id)
            except (KeyError):
                raise JobNotFoundError(f"{job_id} is not found")

            result = cast(schemas.JobResultWrapper, job_result.result)

            # check error
            if result.error is not None:
                raise JobExecutionError(result.error)

            # get task result
            snapshot_job_result = schemas.SnapshotJobResult.parse_obj(
                result.result or {}
            )

            # get job definition
            job_definition = schemas.SnapshotJobDefinition.from_job_result(job_result)

        return schemas.SnapshotJobStatus(
            id=job_id,
            is_running=is_running,
            result=snapshot_job_result,
            definition=job_definition,
        )


class YaraScanJobStatusFactory:
    @staticmethod
    async def from_job_id(
        arq_redis: ArqRedis, job_id: str
    ) -> schemas.YaraScanJobStatus:
        job_definition: Optional[schemas.YaraScanJobDefinition] = None
        is_running: bool = True
        try:
            job_definition_ = await get_job_definition(arq_redis=arq_redis, id=job_id)
            job_definition = schemas.YaraScanJobDefinition.from_job_definition(
                job_definition_
            )
        except (KeyError, DeserializationError):
            is_running = False

        job_result: Optional[JobResult] = None
        yara_scan_job_result: Optional[schemas.YaraScanJobResult] = None
        if not is_running:
            try:
                job_result = await get_result(arq_redis=arq_redis, id=job_id)
            except (KeyError):
                raise JobNotFoundError(f"{job_id} is not found")

            result = cast(schemas.JobResultWrapper, job_result.result)

            # check error
            if result.error is not None:
                raise JobExecutionError(result.error)

            # get task result
            scan_results = cast(List[schemas.YaraScanJobResult], result.result or [])
            yara_scan_job_result = schemas.YaraScanJobResult(scan_results=scan_results)

            # get job definition
            job_definition = schemas.YaraScanJobDefinition.from_job_result(job_result)

        return schemas.YaraScanJobStatus(
            id=job_id,
            is_running=is_running,
            result=yara_scan_job_result,
            definition=job_definition,
        )
