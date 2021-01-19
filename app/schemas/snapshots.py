import datetime
from typing import List, Optional, Union, cast
from uuid import UUID

from fastapi_utils.api_model import APIModel
from pydantic import AnyHttpUrl, Field, IPvAnyAddress, validator

from app.schemas.base import AbstractBaseModel
from app.schemas.certificate import Certificate
from app.schemas.classifications import BaseClassification, Classification
from app.schemas.common import Source, Target
from app.schemas.dns_records import BaseDnsRecord, DnsRecord
from app.schemas.html import HTML
from app.schemas.mixins import TimestampMixin
from app.schemas.scripts import BaseScript, Script
from app.schemas.search import BaseSearchResults
from app.schemas.whois import Whois
from app.utils.network import get_hostname_from_url, get_ip_address_by_hostname

# Declare rules related schemas here to prevent circular reference


def remove_sharp_and_question_from_tail(v: str) -> str:
    return v.rstrip("#|?")


class BaseRule(Source, Target):
    """Base Pydantic model for Rule

    Note that this model doesn't have "id" and "created_at" fields.
    """

    name: str = Field(..., title="Name", description="A name of the YARA rule")


class Rule(BaseRule, AbstractBaseModel, TimestampMixin):
    """Full Pydantic model for Rule"""

    updated_at: datetime.datetime
    snapshots: List["Snapshot"] = Field(
        ...,
        title="Snapshots",
        description="A list of matched snapshots. It contains only the latest 10 snapshots.",
    )


class BasicAttributes(APIModel):
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
    status: int = Field(..., title="Status", description="Status code")
    content_length: Optional[int] = Field(
        None, title="Content length", description="Content length"
    )

    @validator(
        "url", pre=True,
    )
    def normalize_url(cls, v: str):
        return remove_sharp_and_question_from_tail(v)

    @validator(
        "submitted_url", pre=True,
    )
    def normalize_submitted_url(cls, v: str):
        return remove_sharp_and_question_from_tail(v)


class BaseSnapshot(BasicAttributes):
    """Base Pydantic model of Snapshot

    Note that this model doesn't have "id" and "created_at" fields.
    """

    headers: dict = Field(..., title="Headers", description="HTTP response headers")
    request: dict = Field(..., title="Request", description="Meta data of HTTP request")
    processing: bool = Field(
        ...,
        title="Processing",
        description="A boolean flag to show a status of background tasks",
    )


class Snapshot(BaseSnapshot, AbstractBaseModel, TimestampMixin):
    """Pydantic model of Snapshot"""

    html: HTML = Field(..., title="HTML")
    certificate: Optional[Certificate] = Field(None, title="Certificate")
    whois: Whois = Field(None, title="Whois")

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


class PlainSnapshot(BasicAttributes, AbstractBaseModel, TimestampMixin):
    """Plain version of Pydantic model of Snapshot"""

    @classmethod
    def field_keys(cls) -> List[str]:
        return list(cls.__fields__.keys())


class SnapshotsSearchResults(BaseSearchResults):
    results: Union[List[PlainSnapshot], List[UUID]]


class CountResponse(APIModel):
    count: int = Field(
        None,
        title="A number of snapshots",
        description="A number of snapshots matched with filters",
    )


class CreateSnapshotPayload(APIModel):
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
    host: Optional[str] = Field(
        None, title="Host", description="Host HTTP header (it only works with HTTPX)"
    )

    @validator("url")
    def hostname_must_resolvable(cls, v):
        hostname = cast(str, get_hostname_from_url(v))
        ip_address = get_ip_address_by_hostname(hostname)
        if ip_address is None:
            raise ValueError(f"Cannot resolve hostname: {hostname}.")
        return v


# Update foward references
Rule.update_forward_refs()
