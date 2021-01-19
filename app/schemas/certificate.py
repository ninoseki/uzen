from app.schemas.base import AbstractResourceModel
from app.schemas.mixin import TimestampMixin


class Certificate(AbstractResourceModel, TimestampMixin):
    """Pydantic model for Certificate"""
