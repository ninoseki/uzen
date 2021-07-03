from dataclasses import dataclass


@dataclass
class IP2ASNResponse:
    ip_address: str
    asn: str
    country_code: str
    description: str
