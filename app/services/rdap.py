from functools import lru_cache
from typing import Dict

from ipwhois import IPWhois
from ipwhois.exceptions import BaseIpwhoisException


class RDAP:
    @staticmethod
    @lru_cache()
    def lookup(ip_address: str) -> Dict[str, str]:
        obj = IPWhois(ip_address)
        try:
            answer = obj.lookup_rdap(depth=1)
            asn = "AS" + answer.get("asn", "")
            country = answer.get("asn_country_code", "")
            description = answer.get("asn_description", "")
            return {
                "ip_address": ip_address,
                "asn": asn,
                "country": country,
                "description": description,
            }
        except (BaseIpwhoisException, AttributeError):
            return {}
