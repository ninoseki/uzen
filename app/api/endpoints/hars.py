from fastapi import APIRouter, HTTPException
from fastapi_cache.coder import PickleCoder
from fastapi_cache.decorator import cache
from tortoise.exceptions import DoesNotExist

from app import models, schemas, types
from app.cache.constants import ONE_DAY

router = APIRouter()


@cache(coder=PickleCoder, expire=ONE_DAY)
async def _get_har_by_snapshot_id(snapshot_id: types.ULID) -> schemas.HAR:
    har = await models.HAR.get_by_snapshot_id(snapshot_id)
    return har.to_model()


@router.get(
    "/{snapshot_id}",
    response_model=schemas.HAR,
    summary="Get a HAR",
)
async def get_har_by_snapshot_id(
    snapshot_id: types.ULID,
) -> schemas.HAR:
    try:
        return await _get_har_by_snapshot_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404,
            detail=f"HAR related to {snapshot_id} is not found",
        )
