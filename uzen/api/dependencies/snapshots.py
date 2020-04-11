from typing import Optional

from fastapi import Query


class SearchFilters:
    def __init__(
        self,
        hostname: Optional[str] = Query(None, title="Hostname"),
        ip_address: Optional[str] = Query(None, title="IP address"),
        asn: Optional[str] = Query(None, title="AS number"),
        server: Optional[str] = Query(None, title="Server"),
        content_type: Optional[str] = Query(None, title="Content type"),
        sha256: Optional[str] = Query(None, title="SHA256"),
        from_at: Optional[str] = Query(
            None, title="From at", description="A datetime format with %Y-%m-%d"
        ),
        to_at: Optional[str] = Query(
            None, title="To at", description="A datetime format with %Y-%m-%d"
        ),
    ):
        self.hostname = hostname
        self.ip_address = ip_address
        self.asn = asn
        self.server = server
        self.content_type = content_type
        self.sha256 = sha256
        self.from_at = from_at
        self.to_at = to_at
