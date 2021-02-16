from functools import partial

import aiometer

from app import models, schemas
from app.services.ip2asn import IP2ASN
from app.services.whois import Whois


class IPAddressFactory:
    @staticmethod
    async def from_ip_address(ip_address: str) -> schemas.IPAddress:
        tasks = [
            partial(Whois.lookup, ip_address),
            partial(IP2ASN.lookup, ip_address),
            partial(models.Snapshot.find_by_ip_address, ip_address),
        ]
        whois, res, snapshots = await aiometer.run_all(tasks)

        asn = res.get("asn", "")
        country_code = res.get("country_code", "")
        description = res.get("description", "")

        return schemas.IPAddress(
            asn=asn,
            country_code=country_code,
            description=description,
            ip_address=ip_address,
            snapshots=snapshots,
            whois=whois,
        )
