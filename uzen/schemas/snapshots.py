import datetime
from typing import List, Optional, Union

from pydantic import AnyHttpUrl, BaseModel, Field, IPvAnyAddress

from uzen.schemas.classifications import BaseClassification, Classification
from uzen.schemas.dns_records import BaseDnsRecord, DnsRecord
from uzen.schemas.rules import Rule
from uzen.schemas.screenshots import BaseScreenshot, Screenshot
from uzen.schemas.scripts import BaseScript, Script


class BasicAttributes(BaseModel):
    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the snapshot")
    submitted_url: AnyHttpUrl = Field(
        ..., title="Submitted URL", description="A submitted URL of the snapshot"
    )
    hostname: str = Field(..., title="Hostname", description="Hostname")
    ip_address: IPvAnyAddress = Field(..., title="IP address", description="IP address")
    asn: str = Field(..., title="ASN", description="AS number")
    server: Optional[str] = Field(None, title="Server", description="Server header")
    content_type: Optional[str] = Field(
        None, title="Content type", description="Content type"
    )


class BaseSnapshot(BasicAttributes):
    """Base Pydantic model of Snapshot

    Note that this model doesn't have "id" and "created_at" fields.
    """

    status: int = Field(..., title="Status", description="Status code")
    content_length: Optional[int] = Field(
        None, title="Content length", description="Content length"
    )
    body: str = Field(..., title="Body", description="HTTP response body")
    sha256: str = Field(
        ..., title="SHA256", description="SHA256 hash of HTTP response body"
    )
    headers: dict = Field(..., title="Headers", description="HTTP response headers")
    whois: Optional[str] = Field(None, title="Whois", description="Whois record")
    certificate: Optional[str] = Field(
        None, title="Certiricate", description="Certificate record"
    )
    request: dict = Field(..., title="Request", description="Meta data of HTTP request")

    scripts: List[Union[Script, BaseScript]] = Field(
        ..., title="Scripts", description="A list of scripts"
    )
    dns_records: List[Union[DnsRecord, BaseDnsRecord]] = Field(
        ..., title="DNS records", description="A list of DNS records"
    )
    classifications: List[Union[Classification, BaseClassification]] = Field(
        ..., title="Classifications", description="A list of classifications"
    )
    rules: List[Rule] = Field(..., title="Rules", description="A list of matched rules")

    screenshot: Optional[Union[BaseScreenshot, Screenshot]] = Field(
        None, title="Screenshot", description="Screenshot"
    )

    class Config:
        orm_mode = True


class Snapshot(BaseSnapshot):
    """Pydantic model of Snapshot

    """

    id: int
    created_at: datetime.datetime


class SearchResult(BasicAttributes):
    """Simplified version of Pydantic model of Snapshot"""

    id: int
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
    url: AnyHttpUrl = Field(..., title="URL", description="A URL to take a snapshot")
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
        None, title="Accept language", description="Accept-Language HTTP header"
    )
    referer: Optional[str] = Field(
        None, title="Referer", description="Referer HTTP header"
    )