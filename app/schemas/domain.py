from typing import List, Optional

from pydantic import Field

from app.schemas.base import APIModel
from app.schemas.dns_record import BaseDNSRecord
from app.schemas.snapshot import Snapshot
from app.schemas.whois import BaseWhois


class Domain(APIModel):
    """Domain"""

    hostname: str = Field(...)
    dns_records: List[BaseDNSRecord] = Field(
        ...,
    )
    whois: Optional[BaseWhois] = Field(None)
    snapshots: List[Snapshot] = Field(...)
