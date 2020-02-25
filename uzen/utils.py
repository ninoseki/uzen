"""Helper utilities and decorators."""
from typing import Optional
from urllib.parse import urlparse
import json
import requests
import socket


def get_hostname_from_url(url: str) -> Optional[str]:
    parsed = urlparse(url)
    if parsed.netloc == "":
        return None
    return parsed.netloc


def get_ip_address_by_hostname(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return None


class IPInfo:
    HOST = "ipinfo.io"
    BASE_URL = "https://{}".format(HOST)

    def __init__(self):
        self.session = requests.Session()

    def geo(self, ip_address: str):
        url = "{}/{}/geo".format(self.BASE_URL, ip_address)
        r = self.session.get(url)
        r.raise_for_status()
        return r.json()

    @classmethod
    def get_geo(cls, ip_address: str):
        instance = cls()
        return instance.geo(ip_address)


def get_country_code_by_ip_address(ip_address: str) -> Optional[str]:
    try:
        json = IPInfo.get_geo(ip_address)
        return json.get("country")
    except Exception as e:
        return None
