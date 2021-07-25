from fastapi import APIRouter
from fastapi_cache.coder import PickleCoder
from fastapi_cache.decorator import cache

from app import schemas
from app.factories.status import StatusFactory

router = APIRouter()


@cache(coder=PickleCoder)
async def get_status() -> schemas.Status:
    return await StatusFactory.from_ipinfo()


@router.get(
    "/",
    response_model=schemas.Status,
    summary="Get a status",
    status_code=200,
)
async def status() -> schemas.Status:
    return await get_status()
