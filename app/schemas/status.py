from typing import Optional

from pydantic import Field, IPvAnyAddress

from app.schemas.base import APIModel


class Status(APIModel):
    """Status of the app"""

    ip_address: IPvAnyAddress = Field(...)
    country_code: Optional[str] = Field(None)
