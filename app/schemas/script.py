from typing import Optional

from pydantic import AnyHttpUrl, Field, IPvAnyAddress

from app.schemas.base import AbstractParentResourceModel
from app.schemas.mixin import TimestampMixin


class Script(AbstractParentResourceModel, TimestampMixin):
    """Script"""

    url: AnyHttpUrl = Field(...)
    ip_address: Optional[IPvAnyAddress] = Field(None)
