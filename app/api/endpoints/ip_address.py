from fastapi import APIRouter

from app import schemas
from app.factories.ip_address import IPAddressFactory

router = APIRouter()


@router.get(
    "/{ip_address}",
    response_model=schemas.IPAddress,
    response_description="Returns information of an IP address",
    summary="Get IP information",
    description="Get an information related to an IP address",
)
async def get(ip_address: str) -> schemas.IPAddress:
    return await IPAddressFactory.from_ip_address(ip_address)
