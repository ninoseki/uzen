import datetime
from typing import Optional

from pydantic import BaseModel, Field


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


class Classification(BaseClassification):
    """Full Pydantic model for Classification

    """

    id: int
    created_at: datetime.datetime
