import datetime
from functools import lru_cache
from typing import Dict, List, Optional, Union, cast
from uuid import UUID

import httpx
from fastapi_utils.api_model import APIModel
from playwright.sync_api import Error, sync_playwright
from pydantic import AnyHttpUrl, Field, IPvAnyAddress, validator

from app.schemas.base import AbstractBaseModel
from app.schemas.certificate import Certificate
from app.schemas.classification import Classification
from app.schemas.common import Source, Target
from app.schemas.dns_record import DnsRecord
from app.schemas.html import HTML
from app.schemas.mixin import TimestampMixin
from app.schemas.script import Script
from app.schemas.search import BaseSearchResults
from app.schemas.stylesheet import Stylesheet
from app.schemas.whois import Whois
from app.types import WaitUntilType
from app.utils.network import get_hostname_from_url, get_ip_address_by_hostname

# Declare rules & devices related schemas here to prevent circular reference


class Viewport(APIModel):
    width: int
    height: int


class DeviceDescriptor(APIModel):
    user_agent: str
    viewport: Viewport
    device_scale_factor: float
    is_mobile: bool
    has_touch: bool


class Device(APIModel):
    name: str
    descriptor: DeviceDescriptor


@lru_cache()
def get_devices() -> List[Device]:
    devices: List[Device] = []

    with sync_playwright() as playwright:
        for name, descriptor in playwright.devices.items():
            devices.append(Device.parse_obj({"name": name, "descriptor": descriptor}))

        return devices


def remove_sharp_and_question_from_tail(v: str) -> str:
    return v.rstrip("#|?")


class BaseRule(Source, Target):
    """Base Pydantic model for Rule

    Note that this model doesn't have "id" and "created_at" fields.
    """

    name: str = Field(
        ..., title="Name", description="A name of the YARA rule", min_length=1
    )


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
    status: int = Field(..., title="Status", description="Status code")

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

    request_headers: dict = Field(...)
    response_headers: dict = Field(...)
    processing: bool = Field(...)


class Snapshot(BaseSnapshot, AbstractBaseModel, TimestampMixin):
    """Pydantic model of Snapshot"""

    html: HTML = Field(..., title="HTML")
    certificate: Optional[Certificate] = Field(None, title="Certificate")
    whois: Whois = Field(None, title="Whois")

    scripts: List[Script] = Field(..., title="Scripts", description="A list of scripts")
    stylesheets: List[Stylesheet] = Field(
        ..., title="Stylesheets", description="A list of stylesheets"
    )
    dns_records: List[DnsRecord] = Field(
        ..., title="DNS records", description="A list of DNS records"
    )
    classifications: List[Classification] = Field(
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
    enable_har: bool = Field(
        False, title="Enable HAR", description="Whether to enable HAR recording"
    )
    headers: Dict[str, str] = Field(
        {}, title="Headers", description="HTTP request headers to use"
    )
    timeout: Optional[int] = Field(
        None, title="Timeout", description="Maximum time to wait for in milliseconds"
    )
    ignore_https_errors: Optional[bool] = Field(
        None, title="Ignore HTTPS erros", description="Whether to ignore HTTPS errors"
    )
    device_name: Optional[str] = Field(
        None, title="Device name", description="Name of a device to emulate"
    )
    wait_until: WaitUntilType = Field(
        "load",
        title="Wait until",
        description="When to consider operation succeeded, defaults to load",
    )

    @validator("url")
    def hostname_must_resolvable(cls, v):
        hostname = cast(str, get_hostname_from_url(v))
        ip_address = get_ip_address_by_hostname(hostname)
        if ip_address is None:
            raise ValueError(f"Cannot resolve hostname: {hostname}.")
        return v

    @validator("device_name")
    def device_check(cls, v):
        if v is None:
            return v

        devices: List[Device] = []
        try:
            devices = get_devices()
        except Error:
            pass

        names = [device.name for device in devices]
        if v not in names:
            raise ValueError(f"{v} is not supported.")
        return v

    @validator("headers", pre=True, always=True)
    def normalize_headers(cls, headers):
        # translates header names to lowercase for consistency
        headers_ = httpx.Headers(headers)
        return dict(headers_)


# Update foward references
Rule.update_forward_refs()
