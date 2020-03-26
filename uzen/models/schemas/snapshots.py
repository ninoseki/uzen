from pydantic import AnyHttpUrl, BaseModel, IPvAnyAddress, Field
from typing import Optional, List
import datetime

from uzen.models.schemas.classifications import Classification
from uzen.models.schemas.dns_records import DnsRecord
from uzen.models.schemas.scripts import Script


class BaseSnapshot(BaseModel):
    """Base Pydantic model of Snapshot

    Note that this model doesn't have "id" and "created_at" fields.
    """

    url: AnyHttpUrl
    submitted_url: AnyHttpUrl
    status: int
    hostname: str
    ip_address: IPvAnyAddress
    asn: str
    server: Optional[str]
    content_type: Optional[str]
    content_length: Optional[int]
    body: str
    sha256: str
    headers: dict
    screenshot: str
    whois: Optional[str]
    certificate: Optional[str]
    request: dict

    class Config:
        orm_mode = True


class Snapshot(BaseSnapshot):
    """Pydantic model of Snapshot

    """

    id: int
    created_at: datetime.datetime
    scripts: List[Script]
    classifications: List[Classification]
    dns_records: List[DnsRecord]


class SearchResult(BaseModel):
    """Simplified version of Pydantic model of Snapshot"""

    id: int
    url: AnyHttpUrl
    submitted_url: AnyHttpUrl
    hostname: str
    ip_address: IPvAnyAddress
    asn: str
    server: Optional[str]
    content_type: Optional[str]
    created_at: datetime.datetime

    @classmethod
    def field_keys(cls) -> List[str]:
        return list(cls.__fields__.keys())


class CountResponse(BaseModel):
    count: int = Field(
        None,
        title="A number of snapshots",
        description="A number of snapshots matched with filters",
    )


class CreateSnapshotPayload(BaseModel):
    url: AnyHttpUrl
    user_agent: Optional[str] = Field(
        None, title="User agent", description="Specific user agent to use"
    )
    timeout: Optional[int] = Field(
        None, title="Timeout", description="Maximum time to wait for in seconds"
    )
    ignore_https_errors: Optional[bool] = Field(
        None, title="Ignore HTTPS erros", description="Whether to ignore HTTPS errors"
    )
    accept_language: Optional[str] = Field(
        None, title="Accept language", description="Accept-Language request HTTP header"
    )
