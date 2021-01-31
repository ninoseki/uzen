from pydantic import AnyHttpUrl, Field

from app.schemas.base import AbstractBaseModel
from app.schemas.file import File
from app.schemas.mixin import TimestampMixin


class Stylesheet(AbstractBaseModel, TimestampMixin):
    """Pydantic model for Stylesheet"""

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the stylesheet")
    file: File = Field(..., title="File", description="A file of the stylesheet")
