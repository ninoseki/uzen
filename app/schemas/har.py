from pydantic import Field

from app.schemas.base import AbstractBaseModel
from app.schemas.mixin import TimestampMixin


class HAR(AbstractBaseModel, TimestampMixin):
    """Pydantic model for HAR"""

    data: dict = Field(..., title="data")
