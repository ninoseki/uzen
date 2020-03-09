import requests
from fastapi import APIRouter, HTTPException

from uzen.models.snapshots import SnapshotModel
from uzen.services.urlscan import URLScan

router = APIRouter()


@router.post(
    "/{uuid}",
    response_model=SnapshotModel,
    response_description="Returns an imported snapshot",
    status_code=201,
    summary="Import data from urlscan.io",
    description="Import scan data from urlscan.io as a snapshot",
)
async def import_from_urlscan(uuid: str) -> SnapshotModel:
    try:
        snapshot = URLScan.import_as_snapshot(uuid)
    except requests.exceptions.HTTPError:
        raise HTTPException(status_code=404, detail=f"{uuid} is not found")

    await snapshot.save()

    return snapshot.to_full_model()
