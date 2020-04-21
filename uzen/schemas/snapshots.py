import datetime
from typing import List, Optional, Union
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, IPvAnyAddress

from uzen.schemas.base import AbstractBaseModel
from uzen.schemas.classifications import BaseClassification, Classification
from uzen.schemas.common import Source, Target
from uzen.schemas.dns_records import BaseDnsRecord, DnsRecord
from uzen.schemas.mixins import TimestampMixin
from uzen.schemas.screenshots import BaseScreenshot, Screenshot
from uzen.schemas.scripts import BaseScript, Script
from uzen.schemas.search import BaseSearchResults

# Declare rules related schemas here to prevent circular reference


class BaseRule(Source, Target):
    """Base Pydantic model for Rule

    Note that this model doesn't have "id" and "created_at" fields.
    """

    name: str = Field(..., title="Name", description="A name of the YARA rule")

    class Config:
        orm_mode = True


class Rule(BaseRule, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for Rule"""

    updated_at: datetime.datetime
    snapshots: List["Snapshot"] = Field(
        ...,
        title="Snapshots",
        description="A list of matched snapshots. It contains only the latest 10 snapshots.",
    )


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
    processing: bool = Field(
        ...,
        title="Processing",
        description="A boolean flag to show a status of background tasks",
    )

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


class Snapshot(BaseSnapshot, AbstractBaseModel, TimestampMixin):
    """Pydantic model of Snapshot"""


class SimplifiedSnapshot(BasicAttributes, AbstractBaseModel, TimestampMixin):
    """Simplified version of Pydantic model of Snapshot"""

    @classmethod
    def field_keys(cls) -> List[str]:
        return list(cls.__fields__.keys())


class SearchResults(BaseSearchResults):
    results: Union[List[SimplifiedSnapshot], List[UUID]]


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


# Update foward references
Rule.update_forward_refs()
