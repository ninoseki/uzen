from fastapi import APIRouter

from app import schemas
from app.factories.domain import DomainFactory

router = APIRouter()


@router.get(
    "/{hostname}",
    response_model=schemas.Domain,
    response_description="Returns information of a domain",
    summary="Get domain information",
    description="Get information related to a domain",
)
async def get(hostname: str) -> schemas.Domain:
    return await DomainFactory.from_hostname(hostname)
