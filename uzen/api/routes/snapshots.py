from typing import List, Optional, cast
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from tortoise.exceptions import DoesNotExist

from uzen.api.dependencies.snapshots import SearchFilters
from uzen.core.exceptions import TakeSnapshotError
from uzen.models.snapshots import Snapshot
from uzen.schemas.snapshots import (
    CreateSnapshotPayload,
    SearchResults,
    SimplifiedSnapshot,
)
from uzen.schemas.snapshots import Snapshot as SnapshotModel
from uzen.schemas.utils import CountResponse
from uzen.services.searchers.snapshots import SnapshotSearcher
from uzen.services.snapshot import save_snapshot, take_snapshot
from uzen.tasks.enrichment import EnrichmentTask
from uzen.tasks.matches import MatchinbgTask
from uzen.tasks.snapshots import UpdateProcessingTask

router = APIRouter()


@router.get(
    "/count",
    response_model=CountResponse,
    response_description="Returns a count of snapshots",
    summary="Count snapshots",
    description="Get a count of snapshots",
    status_code=200,
)
async def count() -> CountResponse:
    count = await Snapshot.count()
    return CountResponse(count=count)


@router.get(
    "/search",
    response_model=SearchResults,
    response_description="Returns a list of matched snapshots",
    summary="Search snapshots",
    description="Searcn snapshtos with filters",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: SearchFilters = Depends(),
) -> SearchResults:
    results = await SnapshotSearcher.search(vars(filters), size=size, offset=offset)
    snapshots = cast(List[SimplifiedSnapshot], results.results)
    return SearchResults(results=snapshots, total=results.total)


@router.get(
    "/{snapshot_id}",
    response_model=SnapshotModel,
    response_description="Returns a snapshot",
    summary="Get a snapshot",
    description="Get a snapshot which has a given id",
)
async def get(snapshot_id: UUID) -> SnapshotModel:
    try:
        snapshot: Snapshot = await Snapshot.get_by_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{snapshot_id} is not found"
        )

    model = cast(SnapshotModel, snapshot.to_model())
    return model


@router.post(
    "/",
    response_model=SnapshotModel,
    response_description="Returns a created snapshot",
    summary="Create a snapshot",
    description="Create a snapshot of a website by using puppeteer",
    status_code=201,
)
async def create(
    payload: CreateSnapshotPayload, background_tasks: BackgroundTasks
) -> SnapshotModel:
    try:
        result = await take_snapshot(
            url=payload.url,
            accept_language=payload.accept_language,
            ignore_https_errors=payload.ignore_https_errors,
            referer=payload.referer,
            timeout=payload.timeout,
            user_agent=payload.user_agent,
        )
    except TakeSnapshotError as e:
        raise HTTPException(status_code=500, detail=str(e))

    snapshot = await save_snapshot(result)

    background_tasks.add_task(EnrichmentTask.process, snapshot)
    background_tasks.add_task(MatchinbgTask.process, snapshot)
    background_tasks.add_task(UpdateProcessingTask.process, snapshot)

    model = cast(SnapshotModel, snapshot.to_model())
    return model


@router.delete(
    "/{snapshot_id}",
    response_description="Returns an empty JSON",
    summary="Delete a snapshot",
    description="Delete a snapshot which has a given ID",
    status_code=204,
)
async def delete(snapshot_id: UUID) -> dict:
    try:
        await Snapshot.delete_by_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{snapshot_id} is not found"
        )

    return {}
