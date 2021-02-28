import datetime
from functools import lru_cache
from typing import Any, Dict, List, Optional, Union, cast
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
from app.schemas.whois import WhoisMetaData
from app.types import WaitUntilType
from app.utils.network import get_hostname_from_url, get_ip_address_by_hostname

# Declare rules & devices related schemas here to prevent circular reference


class Viewport(APIModel):
    """View port"""

    width: int = Field(...)
    height: int = Field(...)


class DeviceDescriptor(APIModel):
    """Device descriptor"""

    user_agent: str = Field(...)
    viewport: Viewport = Field(...)
    device_scale_factor: float = Field(...)
    is_mobile: bool = Field(...)
    has_touch: bool = Field(...)


class Device(APIModel):
    """Device to be used with a browser"""

    name: str = Field(...)
    descriptor: DeviceDescriptor = Field(...)


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
    """Base model for Rule"""

    name: str = Field(
        ..., title="Name", description="A name of the YARA rule", min_length=1
    )


class Rule(BaseRule, AbstractBaseModel, TimestampMixin):
    """Rule"""

    updated_at: datetime.datetime = Field(...)
    snapshots: List["Snapshot"] = Field(
        ...,
        title="Snapshots",
        description="A list of matched snapshots. It contains only the latest 10 snapshots.",
    )


class SnapshotBasicAttributes(APIModel):
    url: AnyHttpUrl = Field(..., title="URL", description="A URL of the snapshot")
    submitted_url: AnyHttpUrl = Field(
        ..., title="Submitted URL", description="A submitted URL of the snapshot"
    )
    hostname: str = Field(..., title="Hostname", description="Hostname")
    ip_address: IPvAnyAddress = Field(..., title="IP address", description="IP address")
    asn: str = Field(..., title="ASN", description="AS number")
    country_code: str = Field(..., title="Country code")
    status: int = Field(..., title="Status", description="Status code")

    @validator(
        "url",
        pre=True,
    )
    def normalize_url(cls, v: str) -> str:
        return remove_sharp_and_question_from_tail(v)

    @validator(
        "submitted_url",
        pre=True,
    )
    def normalize_submitted_url(cls, v: str) -> str:
        return remove_sharp_and_question_from_tail(v)


class BaseSnapshot(SnapshotBasicAttributes):
    """Base model for Snapshot"""

    request_headers: Dict[str, Any] = Field(...)
    response_headers: Dict[str, Any] = Field(...)
    processing: bool = Field(...)


class Snapshot(BaseSnapshot, AbstractBaseModel, TimestampMixin):
    """Snapshot"""

    html: HTML = Field(...)
    certificate: Optional[Certificate] = Field(None)
    whois: WhoisMetaData = Field(None)

    scripts: List[Script] = Field(..., description="A list of scripts")
    stylesheets: List[Stylesheet] = Field(..., description="A list of stylesheets")
    dns_records: List[DnsRecord] = Field(..., description="A list of DNS records")
    classifications: List[Classification] = Field(
        ..., description="A list of classifications"
    )
    rules: List[Rule] = Field(..., description="A list of matched rules")


class PlainSnapshot(SnapshotBasicAttributes, AbstractBaseModel, TimestampMixin):
    """Plain model for Snapshot"""

    @classmethod
    def field_keys(cls) -> List[str]:
        return list(cls.__fields__.keys())


class SnapshotsSearchResults(BaseSearchResults):
    """Search results of snapshots"""

    results: Union[List[PlainSnapshot], List[UUID]] = Field(...)


class CreateSnapshotPayload(APIModel):
    """Payload to create a snapshot"""

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
        None, title="Ignore HTTPS errors", description="Whether to ignore HTTPS errors"
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
    def hostname_must_resolvable(cls, v: str) -> str:
        hostname = cast(str, get_hostname_from_url(v))
        ip_address = get_ip_address_by_hostname(hostname)
        if ip_address is None:
            raise ValueError(f"Cannot resolve hostname: {hostname}.")

        return v

    @validator("device_name")
    def device_check(cls, v: Optional[str]) -> Optional[str]:
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
    def normalize_headers(cls, headers: Dict[str, Any]) -> Dict[str, Any]:
        # translates header names to lowercase for consistency
        headers_ = httpx.Headers(headers)
        return dict(headers_)


# Update forward references
Rule.update_forward_refs()
