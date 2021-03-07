from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi_cache.coder import PickleCoder
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.utils.cache import cache

router = APIRouter()


@cache(coder=PickleCoder)
async def _get_certificate_by_sha256(sha256: str) -> schemas.Certificate:
    certificate = await models.Certificate.get_by_id(sha256)
    certificate = cast(models.Certificate, certificate)
    return certificate.to_model()


@router.get(
    "/{sha256}",
    response_model=schemas.Certificate,
    response_description="Returns a certificate",
    summary="Get a certificate",
    description="Get a certificate which has a given SHA256 fingerprint",
)
async def get_certificate_by_sha256(sha256: str) -> schemas.Certificate:
    try:
        return await _get_certificate_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Certificate:{sha256} is not found"
        )