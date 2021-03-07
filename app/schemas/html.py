from pydantic import Field

from app.schemas.base import AbstractResourceModel, APIModel
from app.schemas.mixin import TimestampMixin


class BaseHTML(APIModel):
    id: str = Field(..., title="SHA256", alias="sha256")


class HTML(AbstractResourceModel, TimestampMixin):
    """HTML"""

    id: str = Field(..., title="SHA256", alias="sha256")
