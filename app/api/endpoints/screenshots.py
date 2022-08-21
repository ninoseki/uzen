from typing import cast
from uuid import uuid4

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app import schemas, types
from app.api.dependencies.arq import get_arq_redis
from app.arq.constants import PREVIEW_TASK_NAME
from app.cache.constants import ONE_HOUR
from app.cache.decorator import cached
from app.utils.screenshot import get_screenshot

router = APIRouter()


@cached(ttl=ONE_HOUR)
async def _get_screenshot_by_snapshot_id(snapshot_id: str) -> bytes:
    return await get_screenshot(str(snapshot_id))


@router.get(
    "/{snapshot_id}",
    responses={
        200: {"content": {"image/png": {}}, "description": "Returns a screenshot."}
    },
    summary="Get a screenshot",
)
async def get_screenshot_by_snapshot_id(
    snapshot_id: types.ULID,
) -> Response:
    screenshot = await _get_screenshot_by_snapshot_id(str(snapshot_id))
    return Response(content=screenshot, media_type="image/png")


@router.get(
    "/preview/{hostname}",
    responses={
        200: {
            "content": {"image/png": {}},
            "description": "Returns a screenshot or an image.",
        }
    },
    summary="Get a live screenshot",
)
async def perview(
    hostname: str,
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> Response:
    job_id = str(uuid4())
    job = await arq_redis.enqueue_job(PREVIEW_TASK_NAME, hostname, _job_id=job_id)
    if job is None:
        raise HTTPException(status_code=500, detail="Something went wrong...")

    job_result = await job.result()
    job_result = cast(schemas.JobResultWrapper, job_result)

    screenshot = cast(bytes, job_result.result)

    return Response(content=screenshot, media_type="image/png")
