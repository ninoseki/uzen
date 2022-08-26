from dataclasses import dataclass


def is_alpha_2_country_code(country_code: str) -> bool:
    # IP2ASN data may contain "Unknown" or "None" as a country code
    return len(country_code) == 2


@dataclass
class IP2ASNResponse:
    ip_address: str
    asn: str
    country_code: str
    description: str

    def __post_init__(self) -> None:
        if not is_alpha_2_country_code(self.country_code):
            self.country_code = ""
