from typing import cast

import httpx
from fastapi import APIRouter, HTTPException
from tortoise.transactions import in_transaction

from uzen.schemas.snapshots import Snapshot
from uzen.services.snapshot import save_snapshot
from uzen.services.urlscan import URLScan

router = APIRouter()


@router.post(
    "/{uuid}",
    response_model=Snapshot,
    response_description="Returns an imported snapshot",
    status_code=201,
    summary="Import data from urlscan.io",
    description="Import scan data from urlscan.io as a snapshot",
)
async def import_from_urlscan(uuid: str) -> Snapshot:
    try:
        result = await URLScan.import_as_snapshot(uuid)
    except httpx.HTTPError:
        raise HTTPException(status_code=404, detail=f"{uuid} is not found")

    snapshot = await save_snapshot(result)

    model = cast(Snapshot, snapshot.to_model())
    return model
