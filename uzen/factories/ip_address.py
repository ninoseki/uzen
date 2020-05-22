from uzen.models.snapshots import Snapshot
from uzen.schemas.ip_address import IPAddressInformation
from uzen.services.rdap import RDAP
from uzen.services.whois import Whois


class IPAddressInformationFactory:
    @staticmethod
    async def from_ip_address(ip_address: str) -> IPAddressInformation:
        res = RDAP.lookup(ip_address)
        whois = Whois.whois(ip_address)
        snapshots = await Snapshot.find_by_ip_address(ip_address)

        ip_address = ip_address
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
