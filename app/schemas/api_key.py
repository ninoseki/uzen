from datetime import datetime
from typing import Optional, Union
from uuid import UUID

from pydantic import Field

from app.schemas.base import APIModel
from app.schemas.mixin import TimestampMixin


class APIKey(APIModel, TimestampMixin):
    id: Union[str, UUID] = Field(..., alias="apiKey")
    is_active: bool = Field(...)
    last_queried_at: Optional[datetime] = Field(None)
    total_queries: int = Field(...)
    memo: Optional[str] = Field(default=None)


class RevokeOrActivateAPIKey(APIModel):
    api_key: Union[str, UUID] = Field(...)


class APIKeyCreate(APIModel):
    memo: Optional[str] = Field(default=None)
