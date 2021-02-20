from typing import List, Optional

from fastapi_utils.api_model import APIModel
from pydantic import Field, IPvAnyAddress

from app.schemas.snapshot import Snapshot
from app.schemas.whois import BaseWhois


class IPAddress(APIModel):
    """Pydantic model for IP informaiton"""

    ip_address: IPvAnyAddress = Field(
        ..., title="IP address", description="An IP address"
    )
    country_code: str = Field(
        ..., title="Country code", description="A country code of an IP address"
    )
    asn: str = Field(..., title="ASN", description="An ASN of an IP address")
    description: str = Field(
        ..., title="Description", description="A dectiption of an IP address"
    )
    whois: Optional[BaseWhois] = Field(
        None, title="Whois", description="A whois record of an IP address"
    )
    snapshots: List[Snapshot] = Field(
        ..., title="Snapshots", description="A list of related snapshots"
    )
