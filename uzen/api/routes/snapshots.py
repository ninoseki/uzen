from typing import List, Optional, cast

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from loguru import logger
from pyppeteer.errors import PyppeteerError
from tortoise.exceptions import DoesNotExist
import requests

from uzen.api.dependencies.snapshots import search_filters
from uzen.models.dns_records import DnsRecord
from uzen.models.schemas.snapshots import CountResponse, CreateSnapshotPayload
from uzen.models.schemas.snapshots import SearchResult, Snapshot as SnapshotModel
from uzen.models.scripts import Script
from uzen.models.snapshots import Snapshot
from uzen.services.browser import Browser
from uzen.services.fake_browser import FakeBrowser
from uzen.services.dns_records import DnsRecordBuilder
from uzen.services.scripts import ScriptBuilder
from uzen.services.snapshot_search import SnapshotSearcher

router = APIRouter()


@router.get(
    "/search",
    response_model=List[SearchResult],
    response_description="Returns a list of matched snapshots",
    summary="Search snapshots",
    description="Searcn snapshtos with filters",
)
async def search(
    size: Optional[int] = None,
    offset: Optional[int] = None,
    filters: dict = Depends(search_filters),
) -> List[SearchResult]:
    snapshots = await SnapshotSearcher.search(filters, size=size, offset=offset)
    snapshots = cast(List[SearchResult], snapshots)
    return snapshots


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
        snapshot: Snapshot = await Snapshot.get(id=snapshot_id).prefetch_related(
            "scripts", "dns_records"
        )
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Snapshot:{id} is not found")

    model = cast(SnapshotModel, snapshot.to_model())
    return model


@router.get(
    "/",
    response_model=List[SearchResult],
    response_description="Returns a list of snapshots",
    summary="List snapshtos",
    description="Get a list of snapshots",
)
async def list(size: int = 100, offset: int = 0) -> List[SearchResult]:
    snapshots = await SnapshotSearcher.search({}, size=size, offset=offset)
    snapshots = cast(List[SearchResult], snapshots)
    return snapshots


async def create_scripts(snapshot: Snapshot):
    scripts = ScriptBuilder.build_from_snapshot(snapshot)
    await Script.bulk_create(scripts)


async def create_dns_records(snapshot: Snapshot):
    records = DnsRecordBuilder.build_from_snapshot(snapshot)
    await DnsRecord.bulk_create(records)


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
    url = payload.url
    user_agent = payload.user_agent
    accept_language = payload.accept_language
    timeout = payload.timeout or 30000
    ignore_https_errors = payload.ignore_https_errors or False

    snapshot = None
    error = None
    try:
        snapshot = await Browser.take_snapshot(
            url,
            user_agent=user_agent,
            accept_language=accept_language,
            timeout=timeout,
            ignore_https_errors=ignore_https_errors,
        )
    except PyppeteerError as e:
        logger.debug(f"Failed to take a snapshot by pyppeteer: {e}")
        error = e

    # fallback to fake browser (requests)
    if snapshot is None:
        logger.debug("Fallback to requests")
        try:
            snapshot = await FakeBrowser.take_snapshot(
                url,
                user_agent=user_agent,
                accept_language=accept_language,
                timeout=timeout,
                ignore_https_errors=ignore_https_errors,
            )
        except requests.RequestException as e:
            logger.debug(f"Failed to take a snapshot by requests: {e}")
            error = e

    if snapshot is None or error is not None:
        raise HTTPException(status_code=500, detail=str(error))

    await snapshot.save()

    background_tasks.add_task(create_scripts, snapshot)
    background_tasks.add_task(create_dns_records, snapshot)

    model = cast(SnapshotModel, snapshot.to_model())
    return model


@router.delete(
    "/{snapshot_id}",
    response_description="Returns an empty JSON",
    summary="Delete a snapshot",
    description="Delete a snapshot which has a given ID",
    status_code=204,
)
async def delete(snapshot_id: int) -> dict:
    try:
        snapshot = await Snapshot.get(id=snapshot_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Snapshot:{id} is not found")

    await snapshot.delete()
    return {}
