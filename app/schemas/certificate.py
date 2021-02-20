import datetime
from typing import Optional

from pydantic import Field

from app.schemas.base import AbstractResourceModel
from app.schemas.mixin import TimestampMixin


class Certificate(AbstractResourceModel, TimestampMixin):
    """Pydantic model for Certificate"""

    not_after: Optional[datetime.datetime] = Field(None)
    not_before: Optional[datetime.datetime] = Field(None)

    issuer: str = Field(...)
    subject: str = Field(...)
