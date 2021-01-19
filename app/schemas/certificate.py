from app.schemas.base import AbstractResourceModel
from app.schemas.mixins import TimestampMixin


class Certificate(AbstractResourceModel, TimestampMixin):
    """Pydantic model for Certificate"""
