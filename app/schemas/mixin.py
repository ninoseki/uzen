import datetime

from pydantic import BaseModel, Field


class TimestampMixin(BaseModel):
    created_at: datetime.datetime = Field(
        ...,
    )
