from pydantic import AnyHttpUrl, Field

from app.schemas.base import AbstractParentResourceModel
from app.schemas.mixin import TimestampMixin


class Stylesheet(AbstractParentResourceModel, TimestampMixin):
    """Pydantic model for Stylesheet"""

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the stylesheet")
