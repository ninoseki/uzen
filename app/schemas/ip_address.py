from typing import List, Optional

from fastapi_utils.api_model import APIModel
from pydantic import Field, IPvAnyAddress

from app.schemas.snapshots import Snapshot


class IPAddress(APIModel):
    """Pydantic model for IP informaiton"""

    ip_address: IPvAnyAddress = Field(
        ..., title="IP address", description="An IP address"
    )
    country: str = Field(..., title="Country", description="A country of an IP address")
    asn: str = Field(..., title="ASN", description="An ASN of an IP address")
    description: str = Field(
        ..., title="Description", description="A dectiption of an IP address"
    )
    whois: Optional[str] = Field(
        None, title="Whois", description="A whois record of an IP address"
    )
    snapshots: List[Snapshot] = Field(
        ..., title="Snapshots", description="A list of related snapshots"
    )
