from fastapi import APIRouter, HTTPException

from app import schemas
from app.factories.ip_address import IPAddressFactory
from app.utils.validator import is_ip_address

router = APIRouter()


@router.get(
    "/{ip_address}",
    response_model=schemas.IPAddress,
    response_description="Returns information of an IP address",
    summary="Get IP information",
    description="Get an information which is related to an IP address",
)
async def get(ip_address: str) -> schemas.IPAddress:
    if not is_ip_address(ip_address):
        raise HTTPException(
            status_code=404,
            detail=f"{ip_address} is not valid",
        )

    return await IPAddressFactory.from_ip_address(ip_address)
