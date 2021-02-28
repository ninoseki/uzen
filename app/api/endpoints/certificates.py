from typing import cast

from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas

router = APIRouter()


@router.get(
    "/{sha256}",
    response_model=schemas.Certificate,
    response_description="Returns a certificate",
    summary="Get a certificate",
    description="Get a certificate which has a given SHA256 fingerprint",
)
async def get(sha256: str) -> schemas.Certificate:
    try:
        certificate = await models.Certificate.get_by_id(sha256)
        certificate = cast(models.Certificate, certificate)
    except DoesNotExist:
        raise HTTPException(
            status_code=404, detail=f"Certificate:{sha256} is not found"
        )

    return certificate.to_model()
