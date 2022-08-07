from typing import Optional
from uuid import uuid4

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException

from app import schemas
from app.api.dependencies.arq import get_arq_redis
from app.api.dependencies.snapshot import SearchFilters
from app.arq.constants import YARA_SCAN_TASK_NAME

router = APIRouter()


@router.post(
    "/scan",
    response_model=schemas.Job,
    summary="Perform YARA scans against snapshots",
)
async def scan(
    payload: schemas.YaraScan,
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.Job:
    task_payload = schemas.YaraScanWithSearchOptions(
        target=payload.target,
        source=payload.source,
        size=size,
        offset=offset,
        filters=filters.to_model(),
    )
    job_id = str(uuid4())
    job = await arq_redis.enqueue_job(YARA_SCAN_TASK_NAME, task_payload, _job_id=job_id)
    if job is not None:
        return schemas.Job(id=job.job_id, type="yara")

    raise HTTPException(status_code=500, detail="Something went wrong...")
