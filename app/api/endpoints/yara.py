from typing import Optional

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends

from app import schemas
from app.api.dependencies.arq import get_arq_redis
from app.api.dependencies.snapshot import SearchFilters
from app.arq.constants import yara_scan_task_name

router = APIRouter()


@router.post(
    "/scan",
    response_model=schemas.Job,
    response_description="Returns a YARA scan job",
    summary="Perform YARA scans against snapshots",
    description="Perform YARA scans against snapshots (which can be narrowed down by filters)",
)
async def scan(
    payload: schemas.YaraScanPayload,
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.Job:
    task_payload = schemas.YaraScanPayloadWithSearchOptions(
        target=payload.target,
        source=payload.source,
        size=size,
        offset=offset,
        filters=vars(filters),
    )
    job = await arq_redis.enqueue_job(yara_scan_task_name, task_payload)
    return schemas.Job(id=job.job_id, type="yara")
