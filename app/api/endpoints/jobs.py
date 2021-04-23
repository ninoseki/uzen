from typing import List, Optional

from arq.connections import ArqRedis
from arq.constants import job_key_prefix, result_key_prefix
from arq.jobs import JobDef, JobResult
from fastapi import APIRouter, Depends, HTTPException

from app import schemas
from app.api.dependencies.arq import get_arq_redis
from app.core.constants import snapshot_task_name

router = APIRouter()


async def is_running_job(arq_redis: ArqRedis, id: str) -> bool:
    key = job_key_prefix + id
    return await arq_redis.exists(key) == 1


async def is_finished_job(arq_redis: ArqRedis, id: str) -> bool:
    key = result_key_prefix + id
    return await arq_redis.exists(key) == 1


async def get_result(arq_redis: ArqRedis, id: str) -> JobResult:
    key = result_key_prefix + id
    return await arq_redis._get_job_result(key)


@router.get(
    "/snapshots/running",
)
async def get_running_snapshot_jobs(
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.SnapshotJobStatus:
    jobs = await arq_redis.queued_jobs()

    snapshot_jobs: List[JobDef] = []
    for job in jobs:
        if job.function == snapshot_task_name:
            snapshot_jobs.append(job)

    return [job for job in snapshot_jobs]


@router.get(
    "/snapshots/{id}",
)
async def get_snapshot_job(
    id: str, arq_redis: ArqRedis = Depends(get_arq_redis)
) -> schemas.SnapshotJobStatus:
    is_running: bool = False
    if await is_running_job(arq_redis=arq_redis, id=id):
        is_running = True

    job_result: Optional[JobResult] = None
    result: Optional[schemas.SnapshotJobResult] = None
    if await is_finished_job(arq_redis=arq_redis, id=id):
        job_result = await get_result(arq_redis=arq_redis, id=id)

        error = job_result.result.get("error")
        if error is not None:
            raise HTTPException(status_code=404, detail=error)

        result = schemas.SnapshotJobResult.parse_obj(job_result.result)

    return schemas.SnapshotJobStatus(id=id, is_running=is_running, result=result)
