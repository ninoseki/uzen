from fastapi_utils.api_model import APIModel
from pydantic import Field

from uzen.schemas.base import AbstractBaseModel
from uzen.schemas.mixins import TimestampMixin


class BaseDnsRecord(APIModel):
    """Base Pydantic model for DnsRecord

    Note that this model doesn't have "id" and "created_at" fields.
    """

    type: str = Field(
        ..., title="Type", description="A type of the DNS record",
    )
    value: str = Field(
        ..., title="Value", description="A value of the DNS record",
    )

    class Config:
        orm_mode = True


class DnsRecord(BaseDnsRecord, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for DnsRecord"""
