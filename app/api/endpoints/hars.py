from uuid import UUID

from fastapi import APIRouter, HTTPException
from fastapi_cache.coder import PickleCoder
from fastapi_cache.decorator import cache
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.cache.constants import ONE_DAY

router = APIRouter()


@cache(coder=PickleCoder, expire=ONE_DAY)
async def _get_har_by_snapshot_id(snapshot_id: UUID) -> schemas.HAR:
    har = await models.HAR.get_by_snapshot_id(snapshot_id)
    return har.to_model()


@router.get(
    "/{snapshot_id}",
    response_model=schemas.HAR,
    response_description="Returns a HAR",
    summary="Get a HAR",
    description="Get a HAR which related to a snapshot",
)
async def get_har_by_snapshot_id(
    snapshot_id: UUID,
) -> schemas.HAR:
    try:
        return await _get_har_by_snapshot_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404,
            detail=f"HAR related to {snapshot_id} is not found",
        )
