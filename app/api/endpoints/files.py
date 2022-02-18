from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi_cache.coder import PickleCoder
from fastapi_cache.decorator import cache
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.cache.constants import ONE_DAY

router = APIRouter()


@cache(coder=PickleCoder, expire=ONE_DAY)
async def _get_file_by_sha256(sha256: str) -> schemas.File:
    file = await models.File.get_by_id(sha256)
    file = cast(models.File, file)
    return file.to_model()


@router.get(
    "/{sha256}",
    response_model=schemas.File,
    summary="Get a file",
)
async def get_file_by_sha256(sha256: str) -> schemas.File:
    try:
        return await _get_file_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"File:{sha256} is not found")
