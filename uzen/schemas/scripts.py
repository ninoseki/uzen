import datetime

from pydantic import AnyHttpUrl, BaseModel, Field


class BaseScript(BaseModel):
    """Base Pydantic model for Script

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the script")
    content: str = Field(..., title="Content", description="A content of the script")
    sha256: str = Field(..., title="SHA256", description="A SHA256 hash of the script")

    class Config:
        orm_mode = True


class Script(BaseScript):
    """Full Pydantic model for Snapshot"""

    id: int
    created_at: datetime.datetime
