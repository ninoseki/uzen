from typing import Set
from urllib.parse import urlparse

from app import models, schemas


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc


class IndicatorsFactory:
    @staticmethod
    def from_snapshot(snapshot: models.Snapshot) -> schemas.Indicators:
        hashes: Set[str] = set()
        hostnames: Set[str] = set()
        ip_addresses = set()

        for script in snapshot.scripts:
            hashes.add(script.file_id)
            hostnames.add(get_hostname(script.url))
            ip_addresses.add(script.ip_address)

        for stylesheet in snapshot.stylesheets:
            hashes.add(stylesheet.file_id)
            hostnames.add(get_hostname(stylesheet.url))
            ip_addresses.add(script.ip_address)

        # reject None and stringify values
        ip_addresses_ = [
            str(ip_address) for ip_address in ip_addresses if ip_address is not None
        ]

        return schemas.Indicators(
            hostnames=list(hostnames), ip_addresses=ip_addresses_, hashes=list(hashes)
        )
