from typing import List, Optional

from fastapi_utils.api_model import APIModel
from pydantic import Field, IPvAnyAddress

from app.schemas.snapshot import Snapshot
from app.schemas.whois import BaseWhois


class IPAddress(APIModel):
    """IP address"""

    ip_address: IPvAnyAddress = Field(
        ...,
    )
    country_code: str = Field(...)
    asn: str = Field(...)
    description: str = Field(...)
    whois: Optional[BaseWhois] = Field(
        None,
    )
    snapshots: List[Snapshot] = Field(..., description="A list of related snapshots")
