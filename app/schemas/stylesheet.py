from pydantic import AnyHttpUrl, Field

from app.schemas.base import AbstractParentResourceModel
from app.schemas.mixin import TimestampMixin


class Stylesheet(AbstractParentResourceModel, TimestampMixin):
    """Stylesheet"""

    url: AnyHttpUrl = Field(...)
