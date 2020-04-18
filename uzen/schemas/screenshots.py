from uuid import UUID

from pydantic import BaseModel, Field

from uzen.schemas.base import AbstractBaseModel


class BaseScreenshot(BaseModel):
    data: str = Field(..., title="Data", description="Base64 encoded png data")

    class Config:
        orm_mode = True


class Screenshot(BaseScreenshot, AbstractBaseModel):
    """Full Pydantic model for Screenshot"""

    snapshot_id: UUID = Field(
        ..., title="Snapshot ID", description="An ID of the snaphsot"
    )
