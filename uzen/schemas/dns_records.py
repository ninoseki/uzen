import datetime

from pydantic import BaseModel, Field


class BaseDnsRecord(BaseModel):
    """Base Pydantic model for DnsRecord

    Note that this model doesn't have "id" and "created_at" fields.
    """

    type: str = Field(
        ..., title="Type", description="A type of the DNS record",
    )
    value: str = Field(
        ..., title="Value", description="A value of the DNS record",
    )

    class Config:
        orm_mode = True


class DnsRecord(BaseDnsRecord):
    """Full Pydantic model for DnsRecord

    """

    id: int
    created_at: datetime.datetime
