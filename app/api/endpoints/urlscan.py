from typing import Any

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app import models, schemas
from app.api.dependencies.verification import verify_api_key
from app.services.urlscan import URLScan
from app.tasks.match import MatchingTask
from app.tasks.snapshot import UpdateProcessingTask

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
    uuid: str, background_tasks: BackgroundTasks, _: Any = Depends(verify_api_key)
) -> schemas.Snapshot:
    try:
        result = await URLScan.import_as_snapshot(uuid)
    except httpx.HTTPError:
        raise HTTPException(status_code=404, detail=f"{uuid} is not found")

    snapshot = await models.Snapshot.save_snapshot_result(result)

    background_tasks.add_task(MatchingTask.process, snapshot)
    background_tasks.add_task(UpdateProcessingTask.process, snapshot)

    snapshot = await models.Snapshot.get_by_id(snapshot.id)
    return snapshot.to_model()
