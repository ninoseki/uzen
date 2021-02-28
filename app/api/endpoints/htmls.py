from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi_cache.coder import PickleCoder
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.utils.cache import cache

router = APIRouter()


@cache(coder=PickleCoder)
async def _get_html_by_sha256(sha256: str) -> schemas.HTML:
    html = await models.HTML.get_by_id(sha256)
    html = cast(models.HTML, html)
    return html.to_model()


@router.get(
    "/{sha256}",
    response_model=schemas.HTML,
    response_description="Returns an html",
    summary="Get a html",
    description="Get an html which has a given SHA256 hash",
)
async def get_html_by_sha256(sha256: str) -> schemas.HTML:
    try:
        return await _get_html_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"HTML:{sha256} is not found")
