async def search_filters(hostname: str = None, ip_address: str = None, asn: str = None, server: str = None, content_type: str = None, sha256: str = None, from_at: str = None, to_at: str = None) -> dict:
    """Filters for snapshot search

    Keyword Arguments:
        hostname {str} -- Hostname (default: {None})
        ip_address {str} -- IP address (default: {None})
        asn {str} -- ASN (default: {None})
        server {str} -- Server (default: {None})
        content_type {str} -- Content type (default: {None})
        sha256 {str} -- SHA256 (default: {None})
        from_at {str} -- From at (default: {None})
        to_at {str} -- To at (default: {None})

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
