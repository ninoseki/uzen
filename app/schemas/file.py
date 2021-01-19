from app.schemas.base import AbstractResourceModel
from app.schemas.mixins import TimestampMixin


class File(AbstractResourceModel, TimestampMixin):
    """Pydantic model for File"""
