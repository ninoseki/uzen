from pydantic import BaseModel
import datetime


class BaseDnsRecord(BaseModel):
    """Base Pydantic model for DnsRecord

    Note that this model doesn't have "id" and "created_at" fields.
    """

    type: str
    value: str

    class Config:
        orm_mode = True


class DnsRecord(BaseDnsRecord):
    """Full Pydantic model for DnsRecord

    """

    id: int
    created_at: datetime.datetime
