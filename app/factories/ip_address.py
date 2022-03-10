from functools import partial
from typing import Optional, cast

import aiometer

from app import dataclasses, models, schemas
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

        snapshots = [snapshot.to_model() for snapshot in snapshots]

        res = cast(Optional[dataclasses.IP2ASNResponse], res)
        asn = res.asn if res is not None else ""
        country_code = res.country_code if res is not None else ""
        description = res.description if res is not None else ""

        return schemas.IPAddress(
            asn=asn,
            country_code=country_code,
            description=description,
            ip_address=ip_address,
            snapshots=snapshots,
            whois=whois,
        )
