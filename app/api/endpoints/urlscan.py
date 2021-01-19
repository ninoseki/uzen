from typing import cast

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException

from app import models, schemas
from app.services.urlscan import URLScan
from app.tasks.matches import MatchinbgTask
from app.tasks.snapshots import UpdateProcessingTask
from app.utils.snapshot import save_snapshot

router = APIRouter()


@router.post(
    "/{uuid}",
    response_model=schemas.Snapshot,
    response_description="Returns an imported snapshot",
    status_code=201,
    summary="Import data from urlscan.io",
    description="Import scan data from urlscan.io as a snapshot",
)
async def import_from_urlscan(
    uuid: str, background_tasks: BackgroundTasks
) -> schemas.Snapshot:
    try:
        result = await URLScan.import_as_snapshot(uuid)
    except httpx.HTTPError:
        raise HTTPException(status_code=404, detail=f"{uuid} is not found")

    snapshot = await save_snapshot(result)

    background_tasks.add_task(MatchinbgTask.process, snapshot)
    background_tasks.add_task(UpdateProcessingTask.process, snapshot)

    snapshot = await models.Snapshot.get_by_id(snapshot.id)
    model = cast(schemas.Snapshot, snapshot.to_model())
    return model
