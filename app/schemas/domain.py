from typing import List, Optional

from fastapi_utils.api_model import APIModel
from pydantic import Field

from app.schemas.dns_record import BaseDnsRecord
from app.schemas.snapshot import Snapshot


class Domain(APIModel):
    """Pydantic model for domain"""

    hostname: str = Field(..., title="Hostname", description="A hostname")
    dns_records: List[BaseDnsRecord] = Field(
        ..., title="DNS records", description="A list of DNS records"
    )
    whois: Optional[str] = Field(
        None, title="Whois", description="A whois record of an IP address"
    )
    snapshots: List[Snapshot] = Field(
        ..., title="Snapshots", description="A list of related snapshots"
    )
