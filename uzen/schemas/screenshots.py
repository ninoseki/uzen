from pydantic import BaseModel, Field


class BaseScreenshot(BaseModel):
    data: str = Field(..., title="Data", description="Base64 encoded png data")

    class Config:
        orm_mode = True


class Screenshot(BaseScreenshot):
    """Full Pydantic model for Screenshot"""

    id: int
    snapshot_id: int = Field(
        ..., title="Snapshot ID", description="An ID of the snaphsot"
    )
