from app.models.snapshots import Snapshot
from app.schemas.ip_address import IPAddressInformation
from app.services.rdap import RDAP
from app.services.whois import Whois


class IPAddressInformationFactory:
    @staticmethod
    async def from_ip_address(ip_address: str) -> IPAddressInformation:
        res = RDAP.lookup(ip_address)
        whois = Whois.whois(ip_address)
        snapshots = await Snapshot.find_by_ip_address(ip_address)

        asn = res.get("asn", "")
        country = res.get("country", "")
        description = res.get("description", "")

        return IPAddressInformation(
            asn=asn,
            country=country,
            description=description,
            ip_address=ip_address,
            snapshots=snapshots,
            whois=whois,
        )
