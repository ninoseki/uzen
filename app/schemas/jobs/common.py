from typing import Any, Optional

from pydantic import Field

from app.schemas.base import APIModel


class Job(APIModel):
    """Job"""

    id: str = Field(...)
    type: str = Field(...)


class JobStatus(APIModel):
    id: str = Field(...)
    is_running: bool = Field(...)


class JobResultWrapper(APIModel):
    result: Optional[Any] = Field(None)
    error: Optional[str] = Field(None)
