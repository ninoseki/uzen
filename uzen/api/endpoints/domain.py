from fastapi import APIRouter

from uzen.factories.domain import DomainInformationFactory
from uzen.schemas.domain import DomainInformation

router = APIRouter()


@router.get(
    "/{hostname}",
    response_model=DomainInformation,
    response_description="Returns information of a domain",
    summary="Get domain information",
    description="Get information related to a domain",
)
async def get(hostname: str) -> DomainInformation:
    return await DomainInformationFactory.from_hostname(hostname)
