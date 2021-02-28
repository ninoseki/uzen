from typing import Union
from uuid import UUID

from fastapi import APIRouter
from fastapi.responses import Response
from fastapi_cache.coder import PickleCoder

from app.services.browser import Browser
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
    description="Get a screenshot which related to a snapshot",
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
async def perview(hostname: str) -> Union[Response]:
    screenshot = await Browser.preview(hostname)
    return Response(content=screenshot, media_type="image/png")
