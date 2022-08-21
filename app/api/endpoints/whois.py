from typing import cast

from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.cache.constants import ONE_DAY
from app.cache.decorator import cached

router = APIRouter()


@cached(ttl=ONE_DAY)
async def _get_whois_by_id(id_: str) -> schemas.Whois:
    whois = await models.Whois.get_by_id(id_)
    whois = cast(models.Whois, whois)
    return whois.to_model()


@router.get(
    "/{whois_id}",
    response_model=schemas.Whois,
    summary="Get a whois",
)
async def get_whois_by_id(whois_id: str) -> schemas.Whois:
    try:
        return await _get_whois_by_id(whois_id)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"Whois:{whois_id} is not found")
