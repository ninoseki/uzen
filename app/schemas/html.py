from app.schemas.base import AbstractResourceModel
from app.schemas.mixins import TimestampMixin


class HTML(AbstractResourceModel, TimestampMixin):
    """Pydantic model for Response"""
