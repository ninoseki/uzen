from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, AnyHttpUrl
from pyppeteer.errors import PyppeteerError
from tortoise.exceptions import DoesNotExist
from typing import Optional, List


from uzen.browser import Browser
from uzen.models import Snapshot, SnapshotModel
from uzen.services.snapshot_search import SnapshotSearcher
from uzen.dependencies import search_filters

router = APIRouter()


@router.get(
    "/search",
    response_model=List[SnapshotModel],
    response_description="Returns a list of matched snapshots",
    summary="Search snapshots",
    description="Searcn snapshtos with filters",
)
async def search(size: Optional[int] = None, offset: Optional[int] = None, filters: dict = Depends(search_filters)) -> List[SnapshotModel]:
    snapshots = await SnapshotSearcher.search(filters, size=size, offset=offset)
    return [snapshot.to_full_model() for snapshot in snapshots]


class CountResponse(BaseModel):
    count: int = Field(
        None,
        title="A number of snapshots",
        description="A number of snapshots matched with filters"
    )


@router.get(
    "/count",
    response_model=CountResponse,
    response_description="Returns a count matched snapshots",
    summary="Count snapshots",
    description="Count a number of snapshot matched with filters",
)
async def count(filters: dict = Depends(search_filters)) -> CountResponse:
    count = await SnapshotSearcher.search(filters, count_only=True)
    return CountResponse(count=count)


@router.get(
    "/{snapshot_id}",
    response_model=SnapshotModel,
    response_description="Returns a snapshot",
    summary="Get a snapshot",
    description="Get a snapshot which has a given id",
)
async def get(snapshot_id: int) -> SnapshotModel:
    try:
        snapshot = await Snapshot.get(id=snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{id} is not found")

    return snapshot.to_full_model()


@router.get(
    "/",
    response_model=List[SnapshotModel],
    response_description="Returns a list of snapshots",
    summary="List snapshtos",
    description="Get a list of snapshots",
)
async def list(size: int = 100, offset: int = 0) -> List[SnapshotModel]:
    snapshots = await SnapshotSearcher.search({}, size=size, offset=offset)
    return [snapshot.to_full_model() for snapshot in snapshots]


class TakeSnapshotPayload(BaseModel):
    url: AnyHttpUrl
    user_agent: Optional[str] = Field(
        None,
        title="User agent",
        description="Specific user agent to use"
    )
    timeout: Optional[int] = Field(
        None,
        title="Timeout",
        description="Maximum time to wait for in seconds"
    )
    ignore_https_errors: Optional[bool] = Field(
        None,
        title="Ignore HTTPS erros",
        description="Whether to ignore HTTPS errors"
    )


@router.post(
    "/",
    response_model=SnapshotModel,
    response_description="Returns a created snapshot",
    summary="Create a snapshot",
    description="Create a snapshot of a website by using puppeteer",
    status_code=201
)
async def create(payload: TakeSnapshotPayload) -> SnapshotModel:
    url = payload.url
    user_agent = payload.user_agent
    timeout = payload.timeout or 30000
    ignore_https_errors = payload.ignore_https_errors or False

    try:
        snapshot = await Browser.take_snapshot(
            url,
            user_agent=user_agent,
            timeout=timeout,
            ignore_https_errors=ignore_https_errors
        )
    except PyppeteerError as e:
        raise HTTPException(status_code=500, detail=str(e))

    await snapshot.save()
    return snapshot.to_full_model()


@router.delete(
    "/{snapshot_id}",
    response_description="Returns an empty JSON",
    summary="Delete a snapshot",
    description="Delete a snapshot which has a given ID",
    status_code=204
)
async def delete(snapshot_id: int) -> dict:
    try:
        snapshot = await Snapshot.get(id=snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{id} is not found")

    await snapshot.delete()
    return {}
