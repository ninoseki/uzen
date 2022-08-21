from typing import cast

from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas
from app.cache.constants import ONE_DAY
from app.cache.decorator import cached
from app.services.html2text import html2text

router = APIRouter()


@cached(ttl=ONE_DAY)
async def _get_html_by_sha256(sha256: str) -> schemas.HTML:
    html = await models.HTML.get_by_id(sha256)
    html = cast(models.HTML, html)
    return html.to_model()


@router.get(
    "/{sha256}",
    response_model=schemas.HTML,
    summary="Get an html",
)
async def get_html_by_sha256(sha256: str) -> schemas.HTML:
    try:
        return await _get_html_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"HTML:{sha256} is not found")


@router.get(
    "/{sha256}/text",
    summary="Get a text of an html",
)
async def get_text_by_sha256(sha256: str) -> str:
    try:
        html = await _get_html_by_sha256(sha256)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"HTML:{sha256} is not found")

    return html2text(html.content)
