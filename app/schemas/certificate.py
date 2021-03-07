import datetime
from typing import Optional

from pydantic import Field

from app.schemas.base import AbstractResourceModel, APIModel
from app.schemas.mixin import TimestampMixin


class CertificateMetaData(APIModel):
    id: str = Field(..., title="SHA256", alias="sha256")

    not_after: Optional[datetime.datetime] = Field(None)
    not_before: Optional[datetime.datetime] = Field(None)

    issuer: str = Field(...)
    subject: str = Field(...)


class Certificate(AbstractResourceModel, TimestampMixin, CertificateMetaData):
    """Certificate"""
