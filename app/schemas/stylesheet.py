from typing import Optional

from pydantic import AnyHttpUrl, Field, IPvAnyAddress

from app.schemas.base import AbstractParentResourceModel
from app.schemas.mixin import TimestampMixin


class Stylesheet(AbstractParentResourceModel, TimestampMixin):
    """Stylesheet"""

    url: AnyHttpUrl = Field(...)
    ip_address: Optional[IPvAnyAddress] = Field(None)
