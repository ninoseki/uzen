from typing import Optional, Union, cast
from uuid import UUID

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from tortoise.exceptions import DoesNotExist

from uzen.models.screenshots import Screenshot
from uzen.schemas.screenshots import BaseScreenshot
from uzen.schemas.screenshots import Screenshot as ScreenshotModel
from uzen.services.browser import Browser

router = APIRouter()


@router.get(
    "/{snapshot_id}",
    response_model=ScreenshotModel,
    responses={
        200: {
            "content": {"image/png": {}},
            "description": "Returns a sreenshot or an image.",
        }
    },
    response_description="Returns a screenshot",
    summary="Get a screenshot",
    description="Get a screenshot which related to a snapshot",
)
async def get_by_snapshot_id(
    snapshot_id: UUID, output_format: Optional[str] = None
) -> Union[ScreenshotModel, Response]:
    try:
        screenshot = await Screenshot.get_by_snapshot_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Screenshot related to {snapshot_id} is not found",
        )

    if output_format == "png":
        return Response(content=screenshot.png, media_type="image/png")

    model = cast(ScreenshotModel, screenshot.to_model())
    return model


@router.get(
    "/preview/{hostname}",
    response_model=BaseScreenshot,
    responses={
        200: {
            "content": {"image/png": {}},
            "description": "Returns a sreenshot or an image.",
        }
    },
    response_description="Returns a screenshot",
    summary="Get a screenshot",
    description="Get a screenshot for previewing",
)
async def perview(
    hostname: str, output_format: Optional[str] = None
) -> Union[BaseScreenshot, Response]:
    screenshot: Screenshot = await Browser.preview(hostname)

    if output_format == "png":
        return Response(content=screenshot.png, media_type="image/png")

    model = cast(BaseScreenshot, screenshot.to_model())
    return model
