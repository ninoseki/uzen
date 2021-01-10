from fastapi_utils.api_model import APIModel
from pydantic import AnyHttpUrl, Field

from uzen.schemas.base import AbstractBaseModel
from uzen.schemas.mixins import TimestampMixin


class File(APIModel):
    """Full Pydantic model for File"""

    id: str = Field(..., title="ID", description="A SHA256 hash of the content")
    content: str = Field(..., title="Contnt", description="Content of the script")


class BaseScript(APIModel):
    """Base Pydantic model for Script

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the script")
    file: File = Field(..., title="File", description="A file of the script")


class Script(BaseScript, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for Snapshot"""
