from typing import Any, Dict

from pydantic import Field

from app.schemas.base import AbstractBaseModel
from app.schemas.mixin import TimestampMixin


class HAR(AbstractBaseModel, TimestampMixin):
    """HAR"""

    data: Dict[str, Any] = Field(...)
