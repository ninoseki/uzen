from app import models, schemas
from app.services.rdap import RDAP
from app.services.whois import Whois


class IPAddressFactory:
    @staticmethod
    async def from_ip_address(ip_address: str) -> schemas.IPAddress:
        res = RDAP.lookup(ip_address)
        whois = Whois.whois(ip_address)
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
