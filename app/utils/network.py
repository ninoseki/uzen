import socket
from typing import Optional
from urllib.parse import urlparse

from app.services.ip2asn import IP2ASN


def get_hostname_from_url(url: str) -> Optional[str]:
    """Get a hostname from a URL

    Arguments:
        url {str} -- URL

    Returns:
        Optional[str] -- A hostname, returns None if an invalid input is given
    """
    parsed = urlparse(url)
    if parsed.hostname == "":
        return None
    return parsed.hostname


def get_ip_address_by_hostname(hostname: str) -> Optional[str]:
    """Get an IP address by a hostname

    Arguments:
        hostname {str} -- Hostname

    Returns:
        Optional[str] -- An IP address, returns None if an error occurs
    """
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


async def get_asn_by_ip_address(ip_address: str) -> Optional[str]:
    """Get ASN by an IP address

    Arguments:
        ip_address {str} -- IP address

    Returns:
        Optional[str] -- ASN as a string, returns None if an error occurs
    """
    res = await IP2ASN.lookup(ip_address)
    return res.asn if res is not None else None


async def get_country_code_by_ip_address(ip_address: str) -> Optional[str]:
    """Get country code by an IP address

    Arguments:
        ip_address {str} -- IP address

    Returns:
        Optional[str] -- Country code, returns None if an error occurs
    """
    res = await IP2ASN.lookup(ip_address)
    return res.country_code if res is not None else None
