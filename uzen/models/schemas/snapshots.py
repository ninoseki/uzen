from pydantic import BaseModel, Field, AnyHttpUrl
from typing import Optional


class CountResponse(BaseModel):
    count: int = Field(
        None,
        title="A number of snapshots",
        description="A number of snapshots matched with filters"
    )


class CreateSnapshotPayload(BaseModel):
    url: AnyHttpUrl
    user_agent: Optional[str] = Field(
        None,
        title="User agent",
        description="Specific user agent to use"
    )
    timeout: Optional[int] = Field(
        None,
        title="Timeout",
        description="Maximum time to wait for in seconds"
    )
    ignore_https_errors: Optional[bool] = Field(
        None,
        title="Ignore HTTPS erros",
        description="Whether to ignore HTTPS errors"
    )
