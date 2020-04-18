from pydantic import AnyHttpUrl, BaseModel, Field

from uzen.schemas.base import AbstractBaseModel
from uzen.schemas.mixins import TimestampMixin


class BaseScript(BaseModel):
    """Base Pydantic model for Script

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the script")
    content: str = Field(..., title="Content", description="A content of the script")
    sha256: str = Field(..., title="SHA256", description="A SHA256 hash of the script")

    class Config:
        orm_mode = True


class Script(BaseScript, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for Snapshot"""
