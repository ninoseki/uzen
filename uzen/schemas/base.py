from uuid import UUID

from pydantic import BaseModel


class AbstractBaseModel(BaseModel):
    """Full Pydantic model for Classification"""

    id: UUID
