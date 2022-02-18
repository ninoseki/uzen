from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi_cache.coder import PickleCoder
from fastapi_cache.decorator import cache
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.cache.constants import ONE_DAY

router = APIRouter()


@cache(coder=PickleCoder, expire=ONE_DAY)
async def _get_certificate_by_sha256(sha256: str) -> schemas.Certificate:
    certificate = await models.Certificate.get_by_id(sha256)
    certificate = cast(models.Certificate, certificate)
    return certificate.to_model()


@router.get(
    "/{sha256}",
    response_model=schemas.Certificate,
    summary="Get a certificate",
)
async def get_certificate_by_sha256(sha256: str) -> schemas.Certificate:
    try:
        return await _get_certificate_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Certificate:{sha256} is not found"
        )
