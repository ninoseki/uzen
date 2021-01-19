from fastapi_utils.api_model import APIModel
from pydantic import AnyHttpUrl, Field

from app.schemas.base import AbstractBaseModel
from app.schemas.file import File
from app.schemas.mixins import TimestampMixin


class BaseScript(APIModel):
    """Base Pydantic model for Script

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the script")
    file: File = Field(..., title="File", description="A file of the script")


class Script(BaseScript, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for Snapshot"""
