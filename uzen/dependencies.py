async def search_filters(hostname: str = None, ip_address: str = None, asn: str = None, server: str = None, content_type: str = None, sha256: str = None, from_at: str = None, to_at: str = None):
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
