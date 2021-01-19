from app.schemas.base import AbstractResourceModel
from app.schemas.mixins import TimestampMixin


class Whois(AbstractResourceModel, TimestampMixin):
    """Pydantic model for Whois"""
