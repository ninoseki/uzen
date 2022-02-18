from app.schemas.base import AbstractResourceModel
from app.schemas.mixin import TimestampMixin


class File(AbstractResourceModel, TimestampMixin):
    """File"""
