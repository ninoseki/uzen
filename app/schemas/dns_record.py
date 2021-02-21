from fastapi_utils.api_model import APIModel
from pydantic import Field

from app.schemas.base import AbstractBaseModel
from app.schemas.mixin import TimestampMixin


class BaseDnsRecord(APIModel):
    """Base model for DNS record"""

    type: str = Field(
        ...,
    )
    value: str = Field(
        ...,
    )

    class Config:
        orm_mode = True


class DnsRecord(BaseDnsRecord, AbstractBaseModel, TimestampMixin):
    """DNS record"""
