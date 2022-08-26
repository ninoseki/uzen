from pydantic import Field

from app.schemas.base import AbstractBaseModel, APIModel
from app.schemas.mixin import TimestampMixin


class BaseDNSRecord(APIModel):
    """Base model for DNS record"""

    type: str = Field(
        ...,
    )
    value: str = Field(
        ...,
    )

    class Config:
        orm_mode = True


class DNSRecord(BaseDNSRecord, AbstractBaseModel, TimestampMixin):
    """DNS record"""
