from typing import List

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, Path

from app import schemas
from app.api.dependencies.arq import get_arq_redis
from app.arq.constants import SNAPSHOT_TASK_NAME
from app.core.exceptions import JobExecutionError, JobNotFoundError
from app.factories.job_statuses import (
    SimilarityScanJobStatusFactory,
    SnapshotJobStatusFactory,
    YaraScanJobStatusFactory,
)

router = APIRouter()


@router.get(
    "/snapshots/running",
    response_model=List[schemas.SnapshotJobDefinition],
    summary="Get a list of snapshot job definitions",
)
async def get_running_snapshot_jobs(
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> List[schemas.SnapshotJobDefinition]:
    jobs = await arq_redis.queued_jobs()

    snapshot_job_definitions: List[schemas.SnapshotJobDefinition] = []
    for job in jobs:
        if job.function == SNAPSHOT_TASK_NAME:
            snapshot_job_definitions.append(
                schemas.SnapshotJobDefinition.from_job_definition(job)
            )

    return snapshot_job_definitions


@router.get(
    "/snapshots/{job_id}",
    response_model=schemas.SnapshotJobStatus,
    summary="Get a snapshot job status",
)
async def get_snapshot_job(
    job_id: str = Path(..., min_length=32),
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.SnapshotJobStatus:
    try:
        status = await SnapshotJobStatusFactory.from_job_id(
            arq_redis=arq_redis, job_id=job_id
        )
        return status
    except JobExecutionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except JobNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/yara/{job_id}",
    response_model=schemas.YaraScanJobStatus,
    summary="Get a YARA scan job status",
)
async def get_yara_scan_job(
    job_id: str = Path(..., min_length=32),
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.YaraScanJobStatus:
    try:
        status = await YaraScanJobStatusFactory.from_job_id(
            arq_redis=arq_redis, job_id=job_id
        )
        return status
    except JobExecutionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except JobNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/similarity/{job_id}",
    response_model=schemas.SimilarityScanJobStatus,
    summary="Get a similarity scan job status",
)
async def get_similarity_scan_job(
    job_id: str = Path(..., min_length=32),
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.SimilarityScanJobStatus:
    try:
        status = await SimilarityScanJobStatusFactory.from_job_id(
            arq_redis=arq_redis, job_id=job_id
        )
        return status
    except JobExecutionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except JobNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
