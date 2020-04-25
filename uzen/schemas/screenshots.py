from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import Field

from uzen.schemas.base import AbstractBaseModel


class BaseScreenshot(APIModel):
    data: str = Field(..., title="Data", description="Base64 encoded png data")


class Screenshot(BaseScreenshot, AbstractBaseModel):
    """Full Pydantic model for Screenshot"""

    snapshot_id: UUID = Field(
        ..., title="Snapshot ID", description="An ID of the snaphsot"
    )
