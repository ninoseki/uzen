import datetime
from typing import Optional

from pydantic import BaseModel


class BaseClassification(BaseModel):
    """Base Pydantic model for Classification 

    Note that this model doesn't have "id" and "created_at" fields.
    """

    name: str
    malicious: bool
    note: Optional[str]

    class Config:
        orm_mode = True


class Classification(BaseClassification):
    """Full Pydantic model for Classification

    """

    id: int
    created_at: datetime.datetime
