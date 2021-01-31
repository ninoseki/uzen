from datetime import date, datetime
from typing import Optional, Union

from fastapi import Query


class SearchFilters:
    def __init__(
        self,
        asn: Optional[str] = Query(None, title="AS number"),
        hostname: Optional[str] = Query(None, title="Hostname"),
        ip_address: Optional[str] = Query(None, title="IP address", alias="ipAddress"),
        html_hash: Optional[str] = Query(
            None, title="SHA256 hash of HTML", alias="htmlHash"
        ),
        script_hash: Optional[str] = Query(
            None, title="SHA256 hash of script", alias="scriptHash"
        ),
        stylesheet_hash: Optional[str] = Query(
            None, title="SHA256 hash of stylesheet", alias="stylesheetHash"
        ),
        certificate_fingerprint: Optional[str] = Query(
            None,
            title="SHA256 fingerprint of X509 certificate",
            alias="certificateFingerprint",
        ),
        status: Optional[int] = Query(None, title="Status"),
        url: Optional[str] = Query(None, title="URL"),
        from_at: Optional[Union[datetime, date]] = Query(
            None, title="From at", description="Datetime or date in ISO 8601 format"
        ),
        fromAt: Optional[Union[datetime, date]] = Query(
            None, description="Alias of from_at"
        ),
        to_at: Optional[Union[datetime, date]] = Query(
            None, title="To at", description="Datetime or date in ISO 8601 format"
        ),
        toAt: Optional[Union[datetime, date]] = Query(
            None, description="Alias of to_at"
        ),
    ):
        self.asn = asn
        self.hostname = hostname
        self.ip_address = ip_address
        self.html_hash = html_hash
        self.script_hash = script_hash
        self.stylesheet_hash = stylesheet_hash
        self.certificate_fingerprint = certificate_fingerprint
        self.status = status
        self.url = url
        self.from_at = from_at or fromAt
        self.to_at = to_at or toAt
