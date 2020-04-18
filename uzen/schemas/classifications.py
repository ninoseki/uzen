from typing import Optional

from pydantic import BaseModel, Field

from uzen.schemas.base import AbstractBaseModel
from uzen.schemas.mixins import TimestampMixin


class BaseClassification(BaseModel):
    """Base Pydantic model for Classification

    Note that this model doesn't have "id" and "created_at" fields.
    """

    name: str = Field(
        ..., title="Name", description="A name of the classification",
    )
    malicious: bool = Field(
        ..., title="Malicious", description="A result of the classification",
    )
    note: Optional[str] = Field(
        None, title="Note", description="A note of the classification",
    )

    class Config:
        orm_mode = True


class Classification(BaseClassification, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for Classification"""
