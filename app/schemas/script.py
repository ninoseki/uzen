from pydantic import AnyHttpUrl, Field

from app.schemas.base import AbstractParentResourceModel
from app.schemas.mixin import TimestampMixin


class Script(AbstractParentResourceModel, TimestampMixin):
    """Script"""

    url: AnyHttpUrl = Field(...)
