from typing import cast
from uuid import UUID

from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from uzen.models.screenshots import Screenshot
from uzen.schemas.screenshots import BaseScreenshot
from uzen.schemas.screenshots import Screenshot as ScreenshotModel
from uzen.services.browser import Browser

router = APIRouter()


@router.get(
    "/{snapshot_id}",
    response_model=ScreenshotModel,
    response_description="Returns a screenshot",
    summary="Get a screenshot",
    description="Get a screenshot which related to a snapshot",
)
async def get_by_snapshot_id(snapshot_id: UUID) -> ScreenshotModel:
    try:
        screenshot: Screenshot = await Screenshot.get_by_snapshot_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Screenshot related to {snapshot_id} is not found",
        )

    model = cast(ScreenshotModel, screenshot.to_model())
    return model


@router.get(
    "/preview/{hostname}",
    response_model=BaseScreenshot,
    response_description="Returns a screenshot",
    summary="Get a screenshot",
    description="Get a screenshot for previewing",
)
async def perview(hostname: str) -> BaseScreenshot:
    screenshot: Screenshot = await Browser.preview(hostname)

    model = cast(BaseScreenshot, screenshot.to_model())
    return model
