from datetime import date, datetime
from typing import Optional, Union

from fastapi import Query


class SearchFilters:
    def __init__(
        self,
        asn: Optional[str] = Query(None, title="AS number"),
        hostname: Optional[str] = Query(None, title="Hostname"),
        ip_address: Optional[str] = Query(None, title="IP address", alias="ipAddress"),
        hash: Optional[str] = Query(None, title="SHA256 hash of resource"),
        certificate_fingerprint: Optional[str] = Query(
            None,
            title="SHA256 fingerprint of X509 certificate",
            alias="certificateFingerprint",
        ),
        status: Optional[int] = Query(None, title="Status"),
        url: Optional[str] = Query(None, title="URL"),
        tag: Optional[str] = Query(None, title="Tag"),
        from_at: Optional[Union[datetime, date]] = Query(
            None,
            title="From at",
            description="Datetime or date in ISO 8601 format",
            alias="fromAt",
        ),
        to_at: Optional[Union[datetime, date]] = Query(
            None,
            title="To at",
            description="Datetime or date in ISO 8601 format",
            alias="toAt",
        ),
    ):
        self.asn = asn
        self.hostname = hostname
        self.ip_address = ip_address
        self.hash = hash
        self.certificate_fingerprint = certificate_fingerprint
        self.status = status
        self.url = url
        self.tag = tag
        self.from_at = from_at
        self.to_at = to_at
