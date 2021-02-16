from app import models, schemas
from app.services.ip2asn import IP2ASN
from app.services.whois import Whois


class IPAddressFactory:
    @staticmethod
    async def from_ip_address(ip_address: str) -> schemas.IPAddress:
        whois = await Whois.lookup(ip_address)
        res = await IP2ASN.lookup(ip_address)
        snapshots = await models.Snapshot.find_by_ip_address(ip_address)

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
