import datetime
from typing import Optional

from fastapi_utils.api_model import APIModel
from pydantic import Field

from app.schemas.base import AbstractResourceModel
from app.schemas.mixin import TimestampMixin


class BaseWhois(APIModel):
    """Base model for Whois"""

    content: str = Field(..., description="A text of a whois query result")
    created: Optional[datetime.datetime] = Field(None)
    updated: Optional[datetime.datetime] = Field(None)
    expires: Optional[datetime.datetime] = Field(None)
    registrar: Optional[str] = Field(None)
    registrant_name: Optional[str] = Field(None)
    registrant_organization: Optional[str] = Field(None)


class Whois(AbstractResourceModel, TimestampMixin, BaseWhois):
    """Whois"""
