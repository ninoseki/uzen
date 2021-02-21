from typing import Optional

from pydantic import Field

from app.schemas.base import AbstractBaseModel
from app.schemas.mixin import TimestampMixin


class Classification(AbstractBaseModel, TimestampMixin):
    """Classification"""

    name: str = Field(
        ...,
    )
    malicious: bool = Field(
        ...,
    )
    note: Optional[str] = Field(
        None,
    )
