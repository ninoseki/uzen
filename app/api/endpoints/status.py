from fastapi import APIRouter

from app import schemas
from app.factories.status import StatusFactory

router = APIRouter()


@router.get(
    "/",
    response_model=schemas.Status,
    response_description="Returns a status of the app",
    summary="Get a status",
    description="Get a status of the app",
    status_code=200,
)
async def status() -> schemas.Status:
    return await StatusFactory.from_ipinfo()
