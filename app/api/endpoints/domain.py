from fastapi import APIRouter, HTTPException

from app import schemas
from app.factories.domain import DomainFactory
from app.utils.validator import is_domain

router = APIRouter()


@router.get(
    "/{hostname}",
    response_model=schemas.Domain,
    response_description="Returns information of a domain",
    summary="Get domain information",
    description="Get information related to a domain",
)
async def get(hostname: str) -> schemas.Domain:
    if not is_domain(hostname):
        raise HTTPException(
            status_code=404,
            detail=f"{hostname} is not valid",
        )

    return await DomainFactory.from_hostname(hostname)
