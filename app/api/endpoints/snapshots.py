from typing import Any, Dict, List, Optional, cast
from uuid import UUID

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.api.dependencies.arq import get_arq_redis
from app.api.dependencies.snapshot import SearchFilters
from app.api.dependencies.verification import verify_api_key
from app.arq.constants import snapshot_task_name
from app.services.searchers.snapshot import SnapshotSearcher

router = APIRouter()


@router.get(
    "/count",
    response_model=schemas.CountResponse,
    response_description="Returns a count of snapshots",
    summary="Count snapshots",
    description="Get a count of snapshots",
    status_code=200,
)
async def count() -> schemas.CountResponse:
    count_ = await models.Snapshot.count()
    return schemas.CountResponse(count=count_)


@router.get(
    "/search",
    response_model=schemas.SnapshotsSearchResults,
    response_description="Returns a list of matched snapshots",
    summary="Search snapshots",
    description="Search snapshots with filters",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> schemas.SnapshotsSearchResults:
    results = await SnapshotSearcher.search(vars(filters), size=size, offset=offset)
    snapshots = cast(List[schemas.PlainSnapshot], results.results)
    return schemas.SnapshotsSearchResults(results=snapshots, total=results.total)


@router.get(
    "/{snapshot_id}",
    response_model=schemas.Snapshot,
    response_description="Returns a snapshot",
    summary="Get a snapshot",
    description="Get a snapshot which has a given ID",
)
async def get(snapshot_id: UUID) -> schemas.Snapshot:
    try:
        snapshot = await models.Snapshot.get_by_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{snapshot_id} is not found"
        )

    return snapshot.to_model()


@router.post(
    "/",
    response_model=schemas.Job,
    response_description="Returns a created snapshot",
    summary="Create a snapshot",
    description="Create a snapshot of a website",
    status_code=201,
)
async def create(
    payload: schemas.CreateSnapshotPayload,
    _: Any = Depends(verify_api_key),
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.Job:
    job = await arq_redis.enqueue_job(snapshot_task_name, payload)
    return schemas.Job(id=job.job_id, type="snapshot")


@router.delete(
    "/{snapshot_id}",
    response_description="Returns an empty JSON",
    summary="Delete a snapshot",
    description="Delete a snapshot which has a given ID",
    status_code=204,
)
async def delete(snapshot_id: UUID, _: Any = Depends(verify_api_key)) -> Dict[str, Any]:
    try:
        await models.Snapshot.delete_by_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{snapshot_id} is not found"
        )

    return {}
