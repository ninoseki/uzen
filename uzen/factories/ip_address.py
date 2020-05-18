from uzen.models.snapshots import Snapshot
from uzen.schemas.ip_address import IPAddressInformation
from uzen.services.ipinfo import IPInfo
from uzen.services.whois import Whois


class IPAddressInformationFactory:
    @staticmethod
    async def from_ip_address(ip_address: str) -> IPAddressInformation:
        info = await IPInfo.get_info(ip_address)
        whois = Whois.whois(ip_address)
        snapshots = await Snapshot.find_by_ip_address(ip_address)

        ip_address = info.get("ip", "")
        country = info.get("country", "")
        org = info.get("org", "")

        return IPAddressInformation(
            ip_address=ip_address,
            country=country,
            org=org,
            whois=whois,
            snapshots=snapshots,
        )
