from typing import cast

from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas

router = APIRouter()


@router.get(
    "/{whois_id}",
    response_model=schemas.Whois,
    response_description="Returns a whois",
    summary="Get a whois",
)
async def get(whois_id: str) -> schemas.Whois:
    try:
        whois = await models.Whois.get_by_id(whois_id)
        whois = cast(models.Whois, whois)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Whois:{whois_id} is not found")

    return whois.to_model()
