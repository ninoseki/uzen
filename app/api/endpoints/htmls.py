from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi_cache.coder import PickleCoder
from fastapi_cache.decorator import cache
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.services.html2text import html2text

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
    summary="Get an html",
    description="Get an html which has a given SHA256 hash",
)
async def get_html_by_sha256(sha256: str) -> schemas.HTML:
    try:
        return await _get_html_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"HTML:{sha256} is not found")


@router.get(
    "/{sha256}/text",
    response_description="Returns a text of an html",
    summary="Get a text of an html",
    description="Get a text of an html which has a given ID",
)
async def get_text_by_sha256(sha256: str) -> str:
    try:
        html = await _get_html_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"HTML:{sha256} is not found")

    return html2text(html.content)
