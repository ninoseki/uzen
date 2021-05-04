from typing import List

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException, Path

from app import schemas
from app.api.dependencies.arq import get_arq_redis
from app.core.exceptions import JobExecutionError, JobNotFoundError
from app.factories.job_statuses import (
    SimilarityScanJobStatusFactory,
    SnapshotJobStatusFactory,
    YaraScanJobStatusFactory,
)
from app.factories.job_statuses.similarity import RunningSimilarityScanJobsFactory
from app.factories.job_statuses.snapshot import RunningSnapshotJobsFactory
from app.factories.job_statuses.yara import RunningYaraScanJobsFactory

router = APIRouter()


@router.get(
    "/snapshots/running",
    response_model=List[schemas.SnapshotJobDefinition],
    response_description="Returns a list of snapshot job definitions",
    summary="Get a list of snapshot job definitions",
    description="Get a list of snapshot job definitions which are running",
)
async def get_running_snapshot_jobs(
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> List[schemas.SnapshotJobDefinition]:
    return await RunningSnapshotJobsFactory.build(arq_redis=arq_redis)


@router.get(
    "/yara/running",
    response_model=List[schemas.YaraScanJobDefinition],
    response_description="Returns a list of YARA scan job definitions",
    summary="Get a list of YARA scan job definitions",
    description="Get a list of YARA scan job definitions which are running",
)
async def get_running_yara_scan_jobs(
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> List[schemas.YaraScanJobDefinition]:
    return await RunningYaraScanJobsFactory.build(arq_redis=arq_redis)


@router.get(
    "/similarity/running",
    response_model=List[schemas.SimilarityScanJobDefinition],
    response_description="Returns a list of similarity scan job definitions",
    summary="Get a list of similarity scan job definitions",
    description="Get a list of similarity scan job definitions which are running",
)
async def get_running_similarity_scan_jobs(
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> List[schemas.SimilarityScanJobDefinition]:
    return await RunningSimilarityScanJobsFactory.build(arq_redis=arq_redis)


@router.get(
    "/snapshots/{job_id}",
    response_model=schemas.SnapshotJobStatus,
    response_description="Returns a snapshot job status",
    summary="Get a snapshot job status",
    description="Get a snapshot job status which has a given job ID",
)
async def get_snapshot_job(
    job_id: str = Path(..., min_length=32, max_length=32),
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
    response_description="Returns a YARA scan job status",
    summary="Get a YARA scan job status",
    description="Get a YARA scan job status which has a given job ID",
)
async def get_yara_scan_job(
    job_id: str = Path(..., min_length=32, max_length=32),
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
    response_description="Returns a similarity scan job status",
    summary="Get a similarity scan job status",
    description="Get a similarity scan job status which has a given job ID",
)
async def get_similarity_scan_job(
    job_id: str = Path(..., min_length=32, max_length=32),
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
