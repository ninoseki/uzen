from pydantic import AnyHttpUrl, Field

from app.schemas.base import AbstractBaseModel
from app.schemas.file import File
from app.schemas.mixin import TimestampMixin


class Script(AbstractBaseModel, TimestampMixin):
    """Pydantic model for Script"""

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the script")
    file: File = Field(..., title="File", description="A file of the script")
