from app.schemas.base import AbstractResourceModel
from app.schemas.mixin import TimestampMixin


class HTML(AbstractResourceModel, TimestampMixin):
    """Pydantic model for Response"""
