from typing import Any, Dict, List, Optional, cast
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.api.dependencies.snapshot import SearchFilters
from app.api.dependencies.verification import verify_api_key
from app.core.exceptions import TakeSnapshotError
from app.services.browser import Browser
from app.services.searchers.snapshot import SnapshotSearcher
from app.tasks.enrichment import EnrichmentTasks
from app.tasks.match import MatchingTask
from app.tasks.screenshot import UploadScrenshotTask
from app.tasks.snapshot import UpdateProcessingTask

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
    response_model=schemas.Snapshot,
    response_description="Returns a created snapshot",
    summary="Create a snapshot",
    description="Create a snapshot of a website",
    status_code=201,
)
async def create(
    payload: schemas.CreateSnapshotPayload,
    background_tasks: BackgroundTasks,
    _: Any = Depends(verify_api_key),
) -> schemas.Snapshot:
    try:
        ignore_https_error = payload.ignore_https_errors or False
        browser = Browser(
            enable_har=payload.enable_har,
            ignore_https_errors=ignore_https_error,
            timeout=payload.timeout,
            device_name=payload.device_name,
            headers=payload.headers,
            wait_until=payload.wait_until,
        )
        result = await browser.take_snapshot(payload.url)
    except TakeSnapshotError as e:
        raise HTTPException(status_code=500, detail=str(e))

    snapshot = await models.Snapshot.save_snapshot_result(result)

    # add background tasks
    if result.screenshot is not None:
        background_tasks.add_task(
            UploadScrenshotTask.process, uuid=snapshot.id, screenshot=result.screenshot
        )

    background_tasks.add_task(EnrichmentTasks.process, snapshot)
    background_tasks.add_task(MatchingTask.process, snapshot)
    background_tasks.add_task(UpdateProcessingTask.process, snapshot)

    # set required attributes
    snapshot.html = result.html
    snapshot.certificate = result.certificate
    snapshot.whois = result.whois

    return snapshot.to_model()


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
