from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, AnyHttpUrl
from pyppeteer.errors import PyppeteerError
from tortoise.exceptions import DoesNotExist
from typing import Optional, List


from uzen.browser import Browser
from uzen.models import Snapshot, SnapshotModel
from uzen.services.snapshot_search import SnapshotSearcher
from uzen.dependencies import search_filters

router = APIRouter()


@router.get("/search", response_model=List[SnapshotModel])
async def search(size: int = None, offset: int = None, filters: dict = Depends(search_filters)):
    """
    Search snapshots
    """
    snapshots = await SnapshotSearcher.search(filters, size=size, offset=offset)
    return [snapshot.to_full_model() for snapshot in snapshots]


class CountResponse(BaseModel):
    count: int


@router.get("/count", response_model=CountResponse)
async def count(filters: dict = Depends(search_filters)):
    """
    Count snapshots
    """
    count = await SnapshotSearcher.search(filters, count_only=True)
    return CountResponse(count=count)


@router.get("/{snapshot_id}", response_model=SnapshotModel)
async def get(snapshot_id: int):
    """
    Get a snapshot
    """
    try:
        snapshot = await Snapshot.get(id=snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{id} is not found")

    return snapshot.to_full_model()


@router.get("/", response_model=List[SnapshotModel])
async def list(size: int = 100, offset: int = 0):
    """
    List snapshots
    """
    snapshots = await SnapshotSearcher.search({}, size=size, offset=offset)
    return [snapshot.to_full_model() for snapshot in snapshots]


class TakeSnapshotPayload(BaseModel):
    url: AnyHttpUrl
    user_agent: Optional[str]
    timeout: Optional[int]
    ignore_https_errors: Optional[bool]


@router.post("/", response_model=SnapshotModel, status_code=201)
async def create(payload: TakeSnapshotPayload):
    """
    Create a snapshot
    """
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


@router.delete("/{snapshot_id}", status_code=204)
async def delete(snapshot_id: int):
    """
    Delete a snapshot
    """
    try:
        snapshot = await Snapshot.get(id=snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Snapshot:{id} is not found")

    await snapshot.delete()
    return {}
