from fastapi import APIRouter

from uzen.factories.ip_address import IPAddressInformationFactory
from uzen.schemas.ip_address import IPAddressInformation

router = APIRouter()


@router.get(
    "/{ip_address}",
    response_model=IPAddressInformation,
    response_description="Returns information of an IP address",
    summary="Get IP information",
    description="Get an information related to an IP address",
)
async def get(ip_address: str) -> IPAddressInformation:
    return await IPAddressInformationFactory.from_ip_address(ip_address)
