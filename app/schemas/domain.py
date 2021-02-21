from typing import List, Optional

from fastapi_utils.api_model import APIModel
from pydantic import Field

from app.schemas.dns_record import BaseDnsRecord
from app.schemas.snapshot import Snapshot
from app.schemas.whois import BaseWhois


class Domain(APIModel):
    """Domain"""

    hostname: str = Field(...)
    dns_records: List[BaseDnsRecord] = Field(
        ...,
    )
    whois: Optional[BaseWhois] = Field(None)
    snapshots: List[Snapshot] = Field(..., description="A list of related snapshots")
