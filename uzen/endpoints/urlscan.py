from fastapi import APIRouter, HTTPException
from pyppeteer.errors import PyppeteerError
import requests


from uzen.models import SnapshotModel
from uzen.urlscan import URLScan


router = APIRouter()


@router.post("/{uuid}", response_model=SnapshotModel, status_code=201)
async def import_from_urlscan(uuid: str):
    """
    Import a snapshot from urlscan.io
    """
    try:
        snapshot = URLScan.import_as_snapshot(uuid)
    except requests.exceptions.HTTPError:
        raise HTTPException(
            status_code=404, detail=f"{uuid} is not found"
        )

    await snapshot.save()

    return snapshot.to_full_model()
