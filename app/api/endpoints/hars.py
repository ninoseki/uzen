from typing import cast
from uuid import UUID

from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas

router = APIRouter()


@router.get(
    "/{snapshot_id}",
    response_model=schemas.HAR,
    response_description="Returns a HAR",
    summary="Get a HAR",
    description="Get a HAR which related to a snapshot",
)
async def get_by_snapshot_id(
    snapshot_id: UUID,
) -> schemas.HAR:
    try:
        har = await models.HAR.get_by_snapshot_id(snapshot_id)
    except DoesNotExist:
        raise HTTPException(
            status_code=404,
            detail=f"HAR related to {snapshot_id} is not found",
        )

    model = cast(schemas.HAR, har.to_model())
    return model
