from fastapi import APIRouter

from app import schemas
from app.cache.decorator import cached
from app.factories.status import StatusFactory

router = APIRouter()


@cached()
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
