from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas

router = APIRouter()


@router.get(
    "/{sha256}",
    response_model=schemas.File,
    response_description="Returns a file",
    summary="Get a file",
    description="Get a file which has a given SHA256 hash",
)
async def get(sha256: str) -> schemas.File:
    try:
        file = await models.File.get_by_id(sha256)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"File:{sha256} is not found")

    return file.to_model()
