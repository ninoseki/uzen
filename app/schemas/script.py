from pydantic import AnyHttpUrl, Field

from app.schemas.base import AbstractParentResourceModel
from app.schemas.mixin import TimestampMixin


class Script(AbstractParentResourceModel, TimestampMixin):
    """Pydantic model for Script"""

    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the script")
