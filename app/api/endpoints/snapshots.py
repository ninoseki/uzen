from typing import Any, Dict, List, Optional, cast

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, Header, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas, types
from app.api.dependencies.arq import get_arq_redis
from app.api.dependencies.snapshot import SearchFilters
from app.api.dependencies.verification import verify_api_key
from app.arq.constants import SNAPSHOT_TASK_NAME
from app.factories.indicators import IndicatorsFactory
from app.services.searchers.snapshot import SnapshotSearcher
from app.utils.ulid import get_ulid

router = APIRouter()


@router.get(
    "/count",
    response_model=schemas.Count,
    summary="Count snapshots",
    status_code=200,
)
async def count() -> schemas.Count:
    count_ = await models.Snapshot.count()
    return schemas.Count(count=count_)


@router.get(
    "/search",
    response_model=schemas.SnapshotsSearchResults,
    summary="Search snapshots",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> schemas.SnapshotsSearchResults:
    results = await SnapshotSearcher.search(
        filters.to_model(), size=size, offset=offset
    )
    snapshots = cast(List[schemas.PlainSnapshot], results.results)
    return schemas.SnapshotsSearchResults(results=snapshots, total=results.total)


@router.get(
    "/{snapshot_id}",
    response_model=schemas.Snapshot,
    summary="Get a snapshot",
)
async def get(snapshot_id: types.ULID) -> schemas.Snapshot:
    try:
        snapshot = await models.Snapshot.get_by_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{snapshot_id} is not found"
        )

    return snapshot.to_model()


@router.get(
    "/{snapshot_id}/indicators",
    response_model=schemas.Indicators,
    summary="Get indicators related to a snapshot",
)
async def get_indicators(snapshot_id: types.ULID) -> schemas.Indicators:
    try:
        snapshot = await models.Snapshot.get_by_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{snapshot_id} is not found"
        )

    return IndicatorsFactory.from_snapshot(snapshot)


@router.post(
    "/",
    response_model=schemas.Job,
    summary="Create a snapshot",
    status_code=201,
)
async def create(
    payload: schemas.SnapshotCreate,
    api_key: Optional[str] = Header(None),
    *,
    _: Any = Depends(verify_api_key),
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> schemas.Job:
    ulid = get_ulid()
    job_id = str(ulid.to_uuid())

    job = await arq_redis.enqueue_job(
        SNAPSHOT_TASK_NAME, payload, api_key, _job_id=job_id
    )
    if job is None:
        raise HTTPException(status_code=500, detail="Something went wrong...")

    return schemas.Job(id=job_id, type="snapshot")


@router.delete(
    "/{snapshot_id}",
    summary="Delete a snapshot",
    status_code=204,
)
async def delete(
    snapshot_id: types.ULID, _: Any = Depends(verify_api_key)
) -> Dict[str, Any]:
    try:
        await models.Snapshot.delete_by_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{snapshot_id} is not found"
        )

    return {}
