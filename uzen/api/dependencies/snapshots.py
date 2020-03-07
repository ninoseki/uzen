from typing import Optional


async def search_filters(
    hostname: Optional[str] = None,
    ip_address: Optional[str] = None,
    asn: Optional[str] = None,
    server: Optional[str] = None,
    content_type: Optional[str] = None,
    sha256: Optional[str] = None,
    from_at: Optional[str] = None,
    to_at: Optional[str] = None
) -> dict:
    """Filters for snapshot search

    Keyword Arguments:
        hostname {Optional[str]} -- Hostname (default: {None})
        ip_address {Optional[str]} -- IP address (default: {None})
        asn {Optional[str]} -- ASN (default: {None})
        server {Optional[str]} -- Server (default: {None})
        content_type {Optional[str]} -- Content type (default: {None})
        sha256 {Optional[str]} -- SHA256 (default: {None})
        from_at {Optional[str]} -- From at (default: {None})
        to_at {Optional[str]} -- To at (default: {None})

    Returns:
        dict -- filters as a dict
    """
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "asn": asn,
        "server": server,
        "content_type": content_type,
        "sha256": sha256,
        "from_at": from_at,
        "to_at": to_at,
    }
