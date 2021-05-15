from typing import Union, cast
from uuid import UUID

from arq.connections import ArqRedis
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from fastapi_cache.coder import PickleCoder

from app import schemas
from app.api.dependencies.arq import get_arq_redis
from app.arq.constants import PREVIEW_TASK_NAME
from app.utils.cache import cache
from app.utils.screenshot import get_screenshot

router = APIRouter()


@cache(coder=PickleCoder)
async def _get_screenshot_by_snapshot_id(snapshot_id: str) -> bytes:
    return await get_screenshot(str(snapshot_id))


@router.get(
    "/{snapshot_id}",
    responses={
        200: {"content": {"image/png": {}}, "description": "Returns a screenshot."}
    },
    response_description="Returns a screenshot",
    summary="Get a screenshot",
    description="Get a screenshot which is related to a snapshot",
)
async def get_screenshot_by_snapshot_id(
    snapshot_id: UUID,
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
    response_description="Returns a screenshot",
    summary="Get a screenshot",
    description="Get a screenshot for previewing",
)
async def perview(
    hostname: str,
    arq_redis: ArqRedis = Depends(get_arq_redis),
) -> Union[Response]:
    job = await arq_redis.enqueue_job(PREVIEW_TASK_NAME, hostname)
    if job is None:
        raise HTTPException(status_code=500, detail="Something went wrong...")

    job_result = await job.result()
    job_result = cast(schemas.JobResultWrapper, job_result)

    screenshot = cast(bytes, job_result.result)

    return Response(content=screenshot, media_type="image/png")
