from typing import cast

from fastapi import APIRouter, HTTPException
from tortoise.exceptions import DoesNotExist

from app import models, schemas

router = APIRouter()


@router.get(
    "/{sha256}",
    response_model=schemas.HTML,
    response_description="Returns an html",
    summary="Get a html",
    description="Get an html which has a given SHA256 hash",
)
async def get(sha256: str) -> schemas.HTML:
    try:
        html = await models.HTML.get_by_id(sha256)
        html = cast(models.HTML, html)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail=f"HTML:{sha256} is not found")

    return html.to_model()
