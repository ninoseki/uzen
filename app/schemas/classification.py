from typing import Optional

from pydantic import Field

from app.schemas.base import AbstractBaseModel
from app.schemas.mixin import TimestampMixin


class Classification(AbstractBaseModel, TimestampMixin):
    """Pydantic model for Classification"""

    name: str = Field(
        ...,
        title="Name",
        description="A name of the classification",
    )
    malicious: bool = Field(
        ...,
        title="Malicious",
        description="A result of the classification",
    )
    note: Optional[str] = Field(
        None,
        title="Note",
        description="A note of the classification",
    )
