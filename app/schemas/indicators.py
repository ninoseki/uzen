from typing import List

from pydantic import Field

from app.schemas.base import APIModel


class Indicators(APIModel):
    """Indicators"""

    hostnames: List[str] = Field(...)
    ip_addresses: List[str] = Field(...)
    hashes: List[str] = Field(...)
